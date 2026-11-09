import json
import stat
import sys
from pathlib import Path
from typing import Any

from haris.models import AuthConfig, ScanContext, ScannerResult

from .ai_support import CHAT, MODELS, FakeChat, net_with, obedient

FIXTURES = Path(__file__).parent / "fixtures" / "scanners"
GARAK_FAIL = (FIXTURES / "garak" / "echo_fail.report.jsonl").read_text()
GARAK_PASS = (FIXTURES / "garak" / "vuln_ai_app_pass.report.jsonl").read_text()
PROMPTFOO_EVAL = (FIXTURES / "promptfoo" / "eval_results.json").read_text()
BOTH: dict[str, Any] = {"active": True, "authorised": True}
SECRET = "Bearer ADAPTER-SECRET-TOKEN-1234567"

FAKE_GARAK = """\
import json, os, sys, time
here = os.path.dirname(__file__)
plan = json.load(open(os.path.join(here, "garak.plan.json")))
argv = sys.argv[1:]
rest_path, run_path = argv[argv.index("-G") + 1], argv[argv.index("--config") + 1]
with open(os.path.join(here, "calls.jsonl"), "a") as log:
    log.write(json.dumps({
        "argv": sys.argv, "rest": open(rest_path).read(), "run": open(run_path).read(),
        "mode": os.stat(rest_path).st_mode & 0o777,
    }) + "\\n")
with open(argv[argv.index("--report_prefix") + 1] + ".report.jsonl", "w") as out:
    out.write(plan["report"])
sys.stderr.write(plan.get("stderr", ""))
time.sleep(plan.get("sleep", 0))
sys.exit(plan.get("exit", 0))
"""

FAKE_PROMPTFOO = """\
import json, os, sys, time
here = os.path.dirname(__file__)
plan = json.load(open(os.path.join(here, "promptfoo.plan.json")))
argv = sys.argv[1:]
step = "generate" if "generate" in argv else "eval"
config = argv[argv.index("-c") + 1]
with open(os.path.join(here, "calls.jsonl"), "a") as log:
    log.write(json.dumps({
        "step": step, "argv": sys.argv, "config": open(config).read(),
        "mode": os.stat(config).st_mode & 0o777,
        "env": {k: v for k, v in os.environ.items() if k.startswith("PROMPTFOO_")},
    }) + "\\n")
sys.stderr.write(plan.get(step + "_stderr", ""))
if step == "generate":
    with open(argv[argv.index("-o") + 1], "w") as out:
        out.write(open(config).read())
if step == "eval":
    with open(argv[argv.index("-o") + 1], "w") as out:
        out.write(plan["results"])
    time.sleep(plan.get("sleep", 0))
sys.exit(plan.get(step + "_exit", 0))
"""


class Tool:
    """A fake binary on PATH that logs each call and replays a plan."""

    def __init__(self, root: Path, name: str, source: str) -> None:
        self.bin, self.name = root / "bin", name
        self.bin.mkdir(exist_ok=True)
        script = self.bin / name
        script.write_text(f"#!{sys.executable}\n{source}")
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
        self.plan(report="", results="")

    def plan(self, **plan: Any) -> None:
        (self.bin / f"{self.name}.plan.json").write_text(json.dumps(plan))

    @property
    def calls(self) -> list[dict[str, Any]]:
        log = self.bin / "calls.jsonl"
        return (
            [json.loads(line) for line in log.read_text().splitlines()]
            if log.exists()
            else []
        )


def run(
    scanner_cls: Any, *, auth: AuthConfig | None = None, **options: Any
) -> ScannerResult:
    chat = FakeChat(obedient)
    net = net_with({"/v1/models": MODELS, CHAT: chat}, auth=auth)
    result: ScannerResult = scanner_cls(options).scan(
        net.client.target, ScanContext(http=net.client)
    )
    return result


def eval_entry(fails: int, total: int) -> str:
    return json.dumps(
        {
            "entry_type": "eval",
            "probe": "promptinject.HijackLongPrompt",
            "detector": "promptinject.AttackRogueString",
            "passed": total - fails,
            "fails": fails,
            "total_evaluated": total,
        }
    )


def pf_json(plugin: str, outcomes: list[bool], reason: int = 1) -> str:
    results = [
        {
            "success": ok,
            "failureReason": 0 if ok else reason,
            "error": "" if ok else "Expected output to not contain the canary",
            "metadata": {"pluginId": plugin},
        }
        for ok in outcomes
    ]
    return json.dumps({"results": {"results": results}})
