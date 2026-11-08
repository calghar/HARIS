import logging
import uuid
from typing import Any

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from ...auth.middleware import require_user
from ...auth.models import User
from ...llm.base import (
    create_backend,
    get_available_backends,
    get_default_backend_name,
)
from ...llm.qa import ReportQA
from ...models.chat import Conversation
from ..routing import protected_router
from ..scan_runtime import get_completed_session
from ..state import AppState, get_state

logger = logging.getLogger(__name__)

router = protected_router(tags=["llm"])

CONVERSATION_ID_LENGTH = 12


def _question(body: dict[str, Any]) -> str:
    question = str(body.get("question", "")).strip()
    if not question:
        raise HTTPException(status_code=400, detail="question is required")
    return question


@router.get("/api/llm/backends")
async def llm_backends() -> JSONResponse:
    """Return available LLM backends and which is the current default."""
    return JSONResponse(
        {
            "backends": get_available_backends(),
            "default": get_default_backend_name(),
        }
    )


@router.get(
    "/api/scan/{scan_id}/enrichment",
    responses={404: {"description": "Scan not found or not complete"}},
)
async def get_enrichment(
    scan_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Return LLM enrichment data for a completed scan."""
    session = get_completed_session(state, user, scan_id)
    enrichments = {fid: e.model_dump() for fid, e in session.llm_enrichments.items()}
    chains = [c.model_dump() for c in session.attack_chains]
    triaged = [t.model_dump() for t in session.triaged_findings]
    return JSONResponse(
        {
            "enrichments": enrichments,
            "attack_chains": chains,
            "triaged_findings": triaged,
            "has_enrichment": bool(enrichments or chains or triaged),
        }
    )


@router.post(
    "/api/scan/{scan_id}/ask",
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Scan not found or not complete"},
    },
)
async def ask_about_scan(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    session = get_completed_session(state, user, scan_id)
    body = await request.json()
    question = _question(body)
    try:
        backend_name = body.get("backend") or get_default_backend_name()
        qa = ReportQA(backend=create_backend(backend_name))
        response = qa.ask(session, question)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
            }
        )
    except ImportError as exc:
        return JSONResponse(
            {"error": f"LLM backend not available: {exc}"}, status_code=501
        )
    except Exception as exc:
        logger.exception("LLM query failed for scan %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post(
    "/api/scan/{scan_id}/chat",
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Scan or conversation not found"},
    },
)
async def chat_with_scan(
    scan_id: str,
    request: Request,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Multi-turn chat about a completed scan."""
    session = get_completed_session(state, user, scan_id)
    body = await request.json()
    question = _question(body)
    conv_id = body.get("conversation_id")
    state.conversations.evict_expired()

    conv: Conversation | None = None
    if conv_id:
        conv = state.conversations.get(conv_id, scan_id, user)
        if conv is None and state.conversations.exists(conv_id):
            raise HTTPException(status_code=404, detail="Conversation not found")
    try:
        backend_name = body.get("backend") or get_default_backend_name()
        if conv is None:
            conv = Conversation(
                conversation_id=uuid.uuid4().hex[:CONVERSATION_ID_LENGTH],
                scan_id=scan_id,
                backend_name=backend_name,
            )
            state.conversations.add(conv, user.user_id)
        qa = ReportQA(backend=create_backend(backend_name))

        if session.template_id:
            tpl = state.store.get_scan_config_template(session.template_id)
            if tpl:
                question = (
                    f"[Context: This scan used configuration template "
                    f"'{tpl.name}': {tpl.description}. "
                    f"Profile: {tpl.profile}.]\n\n{question}"
                )

        response = qa.chat(session, question, conv.messages)
        conv.add_message("user", question)
        conv.add_message("assistant", response.text, token_count=response.token_count)
        return JSONResponse(
            {
                "answer": response.text,
                "model": response.model,
                "tokens": response.token_count,
                "conversation_id": conv.conversation_id,
                "message_count": conv.message_count,
                "total_tokens": conv.total_tokens,
            }
        )
    except ImportError as exc:
        return JSONResponse(
            {"error": f"LLM backend not available: {exc}"}, status_code=501
        )
    except Exception as exc:
        logger.exception("Chat failed for scan %s", scan_id)
        return JSONResponse({"error": str(exc)}, status_code=500)


def _owned_conversation(
    state: AppState, user: User, scan_id: str, conversation_id: str
) -> Conversation:
    """Conversation readable by the user on a scan they may see, else 404."""
    get_completed_session(state, user, scan_id)
    conv = state.conversations.get(conversation_id, scan_id, user)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@router.get(
    "/api/scan/{scan_id}/chat/{conversation_id}",
    responses={404: {"description": "Conversation not found"}},
)
async def get_conversation(
    scan_id: str,
    conversation_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Retrieve conversation history."""
    conv = _owned_conversation(state, user, scan_id, conversation_id)
    return JSONResponse(
        {
            "conversation_id": conv.conversation_id,
            "messages": [m.model_dump() for m in conv.messages],
            "total_tokens": conv.total_tokens,
        }
    )


@router.delete(
    "/api/scan/{scan_id}/chat/{conversation_id}",
    responses={404: {"description": "Conversation not found"}},
)
async def delete_conversation(
    scan_id: str,
    conversation_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> JSONResponse:
    """Clear a conversation."""
    _owned_conversation(state, user, scan_id, conversation_id)
    state.conversations.delete(conversation_id)
    return JSONResponse({"deleted": conversation_id})
