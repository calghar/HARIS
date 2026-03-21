"""Tests for the ModelRouter task-based LLM routing."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from src.llm.router import ModelRouter


def _make_default_backend(
    name: str = "anthropic",
    model: str = "default-model",
) -> MagicMock:
    """Build a minimal mock backend that ModelRouter will inspect."""
    backend = MagicMock()
    backend.name = name
    backend.model = model
    return backend


class TestModelRouterDefault:
    def test_default_backend_when_no_routing(self):
        """When no routing dict is supplied, for_task always returns the default."""
        default = _make_default_backend()
        router = ModelRouter(default_backend=default)

        assert router.for_task("summary") is default
        assert router.for_task("enrichment") is default
        assert router.for_task("triage") is default

    def test_default_backend_when_task_not_in_routing(self):
        """A task absent from the routing table falls through to the default."""
        default = _make_default_backend()
        router = ModelRouter(default_backend=default, routing={"summary": "fast-model"})

        assert router.for_task("enrichment") is default

    def test_default_backend_when_routed_model_matches_default(self):
        """If the routing model equals default.model, the same instance is returned."""
        default = _make_default_backend(model="my-model")
        router = ModelRouter(default_backend=default, routing={"summary": "my-model"})

        assert router.for_task("summary") is default


class TestModelRouterRouting:
    def test_routed_task_uses_specified_model(self):
        """create_backend is called with the model named in the routing dict."""
        default = _make_default_backend(name="anthropic", model="default-model")
        routed_backend = MagicMock()

        with patch(
            "src.llm.router.create_backend",
            return_value=routed_backend,
        ) as mock_create:
            router = ModelRouter(
                default_backend=default,
                routing={"summary": "fast-model"},
            )
            result = router.for_task("summary")

        mock_create.assert_called_once_with("anthropic", model="fast-model")
        assert result is routed_backend

    def test_routed_backend_is_returned_not_default(self):
        """The returned backend for a routed task is distinct from the default."""
        default = _make_default_backend(model="default-model")
        routed_backend = MagicMock()

        with patch("src.llm.router.create_backend", return_value=routed_backend):
            router = ModelRouter(
                default_backend=default,
                routing={"triage": "cheap-model"},
            )
            result = router.for_task("triage")

        assert result is not default
        assert result is routed_backend


class TestModelRouterFallback:
    def test_unknown_model_falls_back_to_default(self):
        """When create_backend raises, for_task returns the default backend."""
        default = _make_default_backend(model="default-model")

        with patch(
            "src.llm.router.create_backend",
            side_effect=ValueError("unknown model"),
        ):
            router = ModelRouter(
                default_backend=default,
                routing={"summary": "nonexistent-model"},
            )
            result = router.for_task("summary")

        assert result is default

    def test_fallback_does_not_raise(self):
        """A failing create_backend must never propagate the exception."""
        default = _make_default_backend(model="default-model")

        with patch("src.llm.router.create_backend", side_effect=RuntimeError("boom")):
            router = ModelRouter(
                default_backend=default,
                routing={"enrichment": "bad-model"},
            )
            # Should not raise
            result = router.for_task("enrichment")

        assert result is default


class TestModelRouterCache:
    def test_cache_avoids_duplicate_creation(self):
        """Calling for_task with the same task twice creates the backend only once."""
        default = _make_default_backend(model="default-model")
        routed_backend = MagicMock()

        with patch(
            "src.llm.router.create_backend", return_value=routed_backend
        ) as mock_create:
            router = ModelRouter(
                default_backend=default,
                routing={"summary": "fast-model"},
            )
            first = router.for_task("summary")
            second = router.for_task("summary")

        assert mock_create.call_count == 1
        assert first is second

    def test_different_tasks_each_get_their_own_backend(self):
        """Two distinct routed tasks each trigger a separate create_backend call."""
        default = _make_default_backend(model="default-model")
        backend_a = MagicMock()
        backend_b = MagicMock()

        with patch(
            "src.llm.router.create_backend", side_effect=[backend_a, backend_b]
        ) as mock_create:
            router = ModelRouter(
                default_backend=default,
                routing={"summary": "fast-model", "triage": "cheap-model"},
            )
            result_summary = router.for_task("summary")
            result_triage = router.for_task("triage")

        assert mock_create.call_count == 2
        assert result_summary is backend_a
        assert result_triage is backend_b

    def test_cached_backend_returned_after_fallback_not_cached(self):
        """A task that fell back to default is not cached; next call tries again."""
        default = _make_default_backend(model="default-model")
        routed_backend = MagicMock()

        call_results = [ValueError("first attempt fails"), routed_backend]

        with patch(
            "src.llm.router.create_backend",
            side_effect=call_results,
        ) as mock_create:
            router = ModelRouter(
                default_backend=default,
                routing={"summary": "fast-model"},
            )
            first = router.for_task("summary")  # triggers fallback
            second = router.for_task("summary")  # tries again, succeeds

        assert first is default
        assert second is routed_backend
        assert mock_create.call_count == 2
