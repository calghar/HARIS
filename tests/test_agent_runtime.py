from haris.agent.runtime import RuntimeSpec, container_argv
from haris.agent.settings import AgentSettings

FLAGS = (
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--pids-limit",
    "128",
    "--memory",
    "512m",
    "--cpus",
    "1",
    "--user",
    "65534:65534",
)


def _argv() -> list[str]:
    spec = RuntimeSpec(
        name="haris-agent-sbx-unit",
        proxy_url="http://proxy:8080",
        image="sha256:abc",
        network="haris-agent-job-unit",
        api_keys=["sk-testsecretvalue"],
    )
    return container_argv(spec, AgentSettings())


def test_container_argv_matches_the_sandbox_contract():
    """Scenario: Container flags."""
    argv = _argv()
    for flag in FLAGS:
        assert flag in argv
    assert "-v" not in argv
    assert "--volume" not in argv
    assert "--mount" not in argv
    assert "--privileged" not in argv
    assert argv[argv.index("--network") + 1] != "host"
    assert "sk-testsecretvalue" not in argv
    assert all("sk-" not in item for item in argv)


def test_proxy_credentials_are_passed_only_as_the_sandbox_env():
    token = "jobtokenvalue"
    url = f"http://job:{token}@proxy:8080"
    spec = RuntimeSpec(
        name="haris-agent-sbx-unit",
        proxy_url=url,
        image="sha256:abc",
        network="haris-agent-job-unit",
        api_keys=["sk-testsecretvalue"],
    )
    argv = container_argv(spec, AgentSettings())
    assert f"HTTP_PROXY={url}" in argv
    assert f"HTTPS_PROXY={url}" in argv
    assert "sk-testsecretvalue" not in argv
    assert argv.count(f"HTTP_PROXY={url}") == 1
