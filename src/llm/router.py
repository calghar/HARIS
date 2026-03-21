"""Task-based model routing for LLM calls.

Routes different task types (summary, enrichment, triage, etc.)
to different models based on configuration. Falls back to the
default model when no routing is configured for a task type.
"""

import logging

from .base import BaseLLMBackend, create_backend

logger = logging.getLogger(__name__)


class ModelRouter:
    """Routes LLM calls to the appropriate model per task type.

    Usage::

        router = ModelRouter(default_backend, {"summary": "claude-haiku-4-5"})
        backend = router.for_task("summary")  # returns haiku backend
        backend = router.for_task("enrichment")  # returns default
    """

    def __init__(
        self,
        default_backend: BaseLLMBackend,
        routing: dict[str, str] | None = None,
    ) -> None:
        self._default = default_backend
        self._routing = routing or {}
        self._cache: dict[str, BaseLLMBackend] = {}

    def for_task(self, task_type: str) -> BaseLLMBackend:
        """Return a backend configured for the given task type."""
        model = self._routing.get(task_type)
        if not model:
            return self._default

        # Check if the routed model matches default — no need for a new instance
        default_model = getattr(self._default, "model", None)
        if model == default_model:
            return self._default

        # Cache routed backends to avoid re-creation
        if task_type in self._cache:
            return self._cache[task_type]

        try:
            backend = create_backend(self._default.name, model=model)
            self._cache[task_type] = backend
            logger.debug(
                "Routed task %s to model %s",
                task_type,
                model,
            )
            return backend
        except Exception:
            logger.warning(
                "Failed to create routed backend for %s (%s) — using default",
                task_type,
                model,
            )
            return self._default
