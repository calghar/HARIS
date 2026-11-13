import json
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from haris.core.engine import ScanEngine
from haris.data import scanner_config
from haris.models.scan_context import ScanContext
from haris.models.target import Scope, Target
from haris.scanners.nuclei_scanner import BASELINE_TEMPLATE_DIRS, NucleiScanner
from haris.scanners.process import ToolTimeoutError
from tests.conftest import bound_context
from tests.evals.fake_provider import FakeProvider
from tests.test_engine_pipeline import TARGET, Probe

FINDINGS = (
    (Path(__file__).parent / "fixtures" / "scanners" / "nuclei" / "phase2_scan.jsonl")
    .read_text()
    .splitlines()
)
TGL_STDOUT = "\n".join(
    [
        "",
        "Listing available v10.5.2 nuclei tags for /home/haris/nuclei-templates",
        "vuln (7137)",
        "nginx (50)",
        "php (120)",
        "laravel (12)",
    ]
)
DISABLED_NOTE = "template selection: deterministic (selector disabled)"
BOUND_S = 300
BOUND_OPTIONS = {"phase2_timeout_s": BOUND_S}
BOUND_NOTE = (
    f"phase 2 stopped at the {BOUND_S} s limit (scanners.nuclei.phase2_timeout_s); "
    "results so far kept"
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Runner:
    """Fake ``run_process``: records argvs, answers ``-tgl``, advances a stub clock."""

    def __init__(
        self,
        clock: Clock | None = None,
        tags_run: tuple[float, str] = (0.0, ""),
        baseline_run: tuple[float, str] = (0.0, ""),
    ) -> None:
        self.calls: list[tuple[list[str], float]] = []
        self.clock = clock
        self.runs = {"tags": tags_run, "baseline": baseline_run}

    def __call__(self, cmd: list[str], timeout: float) -> tuple[int, str, str]:
        self.calls.append((cmd, timeout))
        if "-tgl" in cmd:
            return 0, TGL_STDOUT, ""
        if "-version" in cmd:
            return 0, "", ""
        seconds, stdout = self.runs["tags" if "-et" in cmd else "baseline"]
        if self.clock is None:
            return 0, stdout, ""
        if seconds > timeout:
            self.clock.now += timeout
            raise ToolTimeoutError("timed out", stdout, "")
        self.clock.now += seconds
        return 0, stdout, ""

    def nuclei_runs(self) -> list[list[str]]:
        return [c for c, _ in self.calls if "-jsonl" in c]

    def tag_group(self) -> list[str]:
        (run,) = [c for c in self.nuclei_runs() if "-et" in c]
        return run

    def baseline_group(self) -> list[str]:
        (run,) = [c for c in self.nuclei_runs() if "-et" not in c]
        return run


def provider(*tags: str) -> FakeProvider:
    return FakeProvider(lambda _: json.dumps({"tags": list(tags)}))


def flag_value(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def run_scan(
    runner: Runner,
    options: dict[str, Any] | None = None,
    context: ScanContext | None = None,
) -> Any:
    scanner = NucleiScanner(options)
    target = Target(base_url="http://127.0.0.1:18080", scope=Scope())
    with ExitStack() as stack:
        stack.enter_context(
            patch.object(scanner, "_check_tool_available", return_value=True)
        )
        stack.enter_context(
            patch.object(scanner, "_check_templates_available", return_value=True)
        )
        stack.enter_context(patch.object(scanner, "_template_root", return_value=None))
        stack.enter_context(
            patch("haris.scanners.base.run_process", side_effect=runner)
        )
        if runner.clock is not None:
            stack.enter_context(
                patch(
                    "haris.scanners.nuclei_scanner.time",
                    SimpleNamespace(monotonic=runner.clock),
                )
            )
        return scanner.scan(target, context or bound_context())


@pytest.fixture
def stack_context() -> ScanContext:
    return bound_context(
        detected_technologies=["nginx", "php"], llm_backend=provider("laravel")
    )


class TestGroupOrder:
    def test_tag_group_runs_before_the_baseline_group(self) -> None:
        runner = Runner()
        run_scan(runner)

        first, second = runner.nuclei_runs()
        assert "-et" in first
        assert "-et" not in second

    def test_et_carries_every_baseline_dir_and_baseline_runs_each_with_t(self) -> None:
        runner = Runner()
        run_scan(runner)

        assert flag_value(runner.tag_group(), "-et") == ",".join(BASELINE_TEMPLATE_DIRS)
        baseline = runner.baseline_group()
        assert [baseline[i + 1] for i, v in enumerate(baseline) if v == "-t"] == list(
            BASELINE_TEMPLATE_DIRS
        )

    def test_one_deadline_spans_both_groups(self) -> None:
        clock = Clock()
        start = clock.now
        runner = Runner(
            clock,
            tags_run=(100.0, FINDINGS[0]),
            baseline_run=(400.0, FINDINGS[1]),
        )
        result = run_scan(runner, BOUND_OPTIONS)

        assert [t for c, t in runner.calls if "-jsonl" in c] == [300.0, 200.0]
        assert clock.now - start == 300.0
        assert result.status == "partial"
        assert result.errors == []
        assert len(result.findings) == 2


class TestSelectedTags:
    def test_map_tags_then_llm_tags_in_argv(self, stack_context: ScanContext) -> None:
        runner = Runner()
        result = run_scan(runner, context=stack_context)

        tags = runner.tag_group()
        assert flag_value(tags, "-tags") == "nginx,php,laravel"
        assert "-as" not in tags
        assert result.note == "template selection: llm tags laravel"

    def test_llm_tag_already_in_the_map_is_not_repeated(self) -> None:
        context = bound_context(
            detected_technologies=["nginx"], llm_backend=provider("nginx", "laravel")
        )
        runner = Runner()
        run_scan(runner, context=context)

        assert flag_value(runner.tag_group(), "-tags") == "nginx,laravel"

    def test_no_tags_uses_the_automatic_scan(self) -> None:
        runner = Runner()
        result = run_scan(runner)

        tags = runner.tag_group()
        assert "-as" in tags
        assert "-tags" not in tags
        assert "-w" not in tags
        assert result.note == DISABLED_NOTE

    def test_empty_llm_answer_with_no_map_tags_uses_the_automatic_scan(self) -> None:
        context = bound_context(
            detected_technologies=["qm-system"], llm_backend=provider()
        )
        runner = Runner()
        result = run_scan(runner, context=context)

        assert "-as" in runner.tag_group()
        assert "-tags" not in runner.tag_group()
        assert result.note == "template selection: llm tags none"

    def test_automatic_scan_option_adds_as_beside_tags(self) -> None:
        context = bound_context(detected_technologies=["nginx"])
        runner = Runner()
        run_scan(runner, {"automatic_scan": True}, context)

        tags = runner.tag_group()
        assert "-as" in tags
        assert flag_value(tags, "-tags") == "nginx"


class TestAllowlistRead:
    def test_no_backend_never_lists_tags(self) -> None:
        runner = Runner()
        run_scan(runner, context=bound_context(detected_technologies=["nginx"]))

        assert not any("-tgl" in c for c, _ in runner.calls)

    def test_backend_lists_tags_without_the_update_check_and_with_configured_bounds(
        self, stack_context: ScanContext
    ) -> None:
        runner = Runner()
        with patch(
            "haris.scanners.nuclei_scanner.read_allowlist",
            return_value=frozenset({"laravel"}),
        ) as spy:
            run_scan(runner, context=stack_context)
        _, deny, minimum, maximum = spy.call_args.args
        assert (deny, minimum, maximum) == (["dos", "intrusive", "fuzz"], 3, 300)

        runner = Runner()
        run_scan(runner, context=stack_context)
        (listing,) = [c for c, _ in runner.calls if "-tgl" in c]
        assert listing == ["nuclei", "-tgl", "-duc"]


class TestNoFingerprintPass:
    @pytest.mark.parametrize(
        "options", [{}, {"automatic_scan": True}, {"tags": ["cves"]}], ids=str
    )
    def test_no_invocation_selects_http_technologies(
        self, options: dict[str, Any], stack_context: ScanContext
    ) -> None:
        runner = Runner()
        run_scan(runner, options, stack_context)

        assert runner.nuclei_runs()
        assert all("http/technologies" not in " ".join(c) for c, _ in runner.calls)


class TestExplicitOptions:
    @pytest.mark.parametrize(
        "options", [{"tags": ["cves"]}, {"template_dirs": ["http/misconfiguration"]}]
    )
    def test_selector_is_not_called(self, options: dict[str, Any]) -> None:
        backend = FakeProvider(lambda _r: pytest.fail("selector called"))
        context = bound_context(detected_technologies=["nginx"], llm_backend=backend)
        runner = Runner()
        result = run_scan(runner, options, context)

        assert backend.requests == []
        assert not any("-tgl" in c for c, _ in runner.calls)
        (single,) = runner.nuclei_runs()
        assert "-et" not in single
        assert (
            result.note
            == "template selection: deterministic (explicit template options)"
        )

    def test_given_tags_reach_argv_unchanged(self) -> None:
        runner = Runner()
        run_scan(runner, {"tags": ["cves"]})

        (single,) = runner.nuclei_runs()
        assert flag_value(single, "-tags") == "cves"


class TestNote:
    def test_partial_run_joins_the_limit_note_and_the_selection_note(
        self, stack_context: ScanContext
    ) -> None:
        clock = Clock()
        runner = Runner(clock, tags_run=(100.0, ""), baseline_run=(400.0, ""))
        result = run_scan(runner, BOUND_OPTIONS, stack_context)

        assert result.status == "partial"
        assert result.note == f"{BOUND_NOTE}; template selection: llm tags laravel"

    def test_completed_run_carries_the_selection_note_alone(self) -> None:
        result = run_scan(Runner())

        assert result.status == "completed"
        assert result.note == DISABLED_NOTE


class TestContextBackend:
    def test_dump_and_repr_exclude_the_backend(self) -> None:
        backend = provider("laravel")
        context = bound_context(llm_backend=backend)

        assert context.llm_backend is backend
        assert "llm_backend" not in context.model_dump()
        assert "llm_backend" not in context.model_dump_json()
        assert "FakeProvider" not in repr(context)

    @pytest.mark.parametrize(("enabled", "passed"), [(True, True), (False, False)])
    def test_engine_passes_the_backend_only_when_enrichment_is_enabled(
        self, enabled: bool, passed: bool
    ) -> None:
        backend = provider()
        probe = Probe("nuclei")
        ScanEngine(
            scanners=[probe],
            llm_backend=backend,
            llm_config={"enrichment_enabled": enabled},
        ).run(TARGET)

        assert probe.context is not None
        assert (probe.context.llm_backend is backend) is passed


class TestConfigValues:
    @pytest.fixture
    def yaml_values(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, Any]]:
        values: dict[str, Any] = {}
        monkeypatch.setattr(scanner_config, "_load_scanner_config", lambda _n: values)
        yield values

    def test_real_yaml_defaults(self) -> None:
        assert scanner_config.get_nuclei_max_selected_tags() == 10
        assert scanner_config.get_nuclei_min_tag_templates() == 3
        assert scanner_config.get_nuclei_max_tag_templates() == 300
        assert scanner_config.get_nuclei_deny_tags() == ["dos", "intrusive", "fuzz"]

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("max_selected_tags", 0),
            ("max_selected_tags", "10"),
            ("max_selected_tags", True),
            ("min_tag_templates", 0),
            ("max_tag_templates", 2),
        ],
    )
    def test_invalid_counts_raise(
        self, yaml_values: dict[str, Any], key: str, value: object
    ) -> None:
        yaml_values.update({"min_tag_templates": 3, key: value})
        getter = {
            "max_selected_tags": scanner_config.get_nuclei_max_selected_tags,
            "min_tag_templates": scanner_config.get_nuclei_min_tag_templates,
            "max_tag_templates": scanner_config.get_nuclei_max_tag_templates,
        }[key]
        with pytest.raises(ValueError, match=f"scanners.nuclei.{key}"):
            getter()

    def test_max_equal_to_min_is_accepted(self, yaml_values: dict[str, Any]) -> None:
        yaml_values.update({"min_tag_templates": 5, "max_tag_templates": 5})
        assert scanner_config.get_nuclei_max_tag_templates() == 5
