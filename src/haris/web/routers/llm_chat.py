import uuid

from fastapi import Depends, HTTPException

from ...auth.middleware import require_user
from ...auth.models import User
from ...llm.base import get_available_backends, get_default_backend_name
from ...models.chat import Conversation
from ..access import Access, scan_access
from ..llm_support import answer, endpoint_display, llm_config, llm_errors, make_qa
from ..routing import api_router
from ..scan_runtime import get_completed_session
from ..schemas.llm import (
    Answer,
    AskIn,
    BackendList,
    ChatAnswer,
    ChatIn,
    ConversationDeleted,
    ConversationOut,
    ConversationSummary,
)
from ..state import AppState, get_state

router = api_router("scans:read", "scans:write", prefix="/llm", tags=["llm"])

CONVERSATION_ID_LENGTH = 12
NOT_FOUND = "Conversation not found"


@router.get("/backends")
async def llm_backends() -> BackendList:
    """The litellm backend: availability, model, endpoint as scheme and host."""
    cfg = llm_config()
    shown = {"model": cfg.model, "endpoint": endpoint_display(cfg.api_base)}
    return BackendList.model_validate(
        {
            "backends": [entry | shown for entry in get_available_backends(cfg.model)],
            "default": get_default_backend_name(),
        }
    )


@router.post(
    "/ask",
    responses={404: {"description": "Scan not found or not complete"}},
)
async def ask_about_scan(
    body: AskIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> Answer:
    session = get_completed_session(state, user, body.scan_id)
    with llm_errors("ask"):
        return answer(make_qa(body.backend).ask(session, body.question))


def _readable_conversation(
    state: AppState, user: User, conversation_id: str
) -> Conversation:
    """Conversation of the user on a scan they may still see, else 404."""
    conv = state.conversations.get(conversation_id, user)
    if conv is None or scan_access(state, user, conv.scan_id) is Access.NONE:
        raise HTTPException(status_code=404, detail=NOT_FOUND)
    return conv


@router.post(
    "/chat",
    responses={404: {"description": "Scan or conversation not found"}},
)
async def chat_with_scan(
    body: ChatIn,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> ChatAnswer:
    """Multi-turn chat about a completed scan."""
    session = get_completed_session(state, user, body.scan_id)
    state.conversations.evict_expired()
    conv: Conversation | None = None
    if body.conversation_id:
        conv = state.conversations.get(body.conversation_id, user)
        if conv is not None and conv.scan_id != body.scan_id:
            raise HTTPException(status_code=404, detail=NOT_FOUND)
        if conv is None and state.conversations.exists(body.conversation_id):
            raise HTTPException(status_code=404, detail=NOT_FOUND)
    question = body.question
    with llm_errors("chat"):
        backend_name = body.backend or llm_config().backend
        qa = make_qa(backend_name)
        if conv is None:
            conv = Conversation(
                conversation_id=uuid.uuid4().hex[:CONVERSATION_ID_LENGTH],
                scan_id=body.scan_id,
                backend_name=backend_name,
            )
            state.conversations.add(conv, user.user_id)
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
        return ChatAnswer(
            **answer(response).model_dump(),
            conversation_id=conv.conversation_id,
            message_count=conv.message_count,
            total_tokens=conv.total_tokens,
        )


@router.get("/conversations")
async def list_conversations(
    user: User = Depends(require_user), state: AppState = Depends(get_state)
) -> list[ConversationSummary]:
    """The caller's conversations (all for admins) on scans still visible to them."""
    return [
        ConversationSummary(
            conversation_id=c.conversation_id,
            scan_id=c.scan_id,
            backend_name=c.backend_name,
            created_at=c.created_at,
            message_count=c.message_count,
            total_tokens=c.total_tokens,
        )
        for c in state.conversations.list_for(user)
        if scan_access(state, user, c.scan_id) is not Access.NONE
    ]


@router.get(
    "/conversations/{conversation_id}", responses={404: {"description": NOT_FOUND}}
)
async def get_conversation(
    conversation_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> ConversationOut:
    conv = _readable_conversation(state, user, conversation_id)
    return ConversationOut.model_validate(
        {
            "conversation_id": conv.conversation_id,
            "messages": [m.model_dump() for m in conv.messages],
            "total_tokens": conv.total_tokens,
        }
    )


@router.delete(
    "/conversations/{conversation_id}", responses={404: {"description": NOT_FOUND}}
)
async def delete_conversation(
    conversation_id: str,
    user: User = Depends(require_user),
    state: AppState = Depends(get_state),
) -> ConversationDeleted:
    _readable_conversation(state, user, conversation_id)
    state.conversations.delete(conversation_id)
    return ConversationDeleted(deleted=conversation_id)
