import shlex
from typing import Any, NamedTuple

import pytest

from haris.models.target import AuthConfig, Target
from haris.scanners.nuclei_scanner import NucleiScanner

BASE_URL = "https://example.com"


class Case(NamedTuple):
    options: dict[str, Any] = {}
    call: dict[str, Any] = {}
    proxy: str = ""
    rate_rps: float = 0.0
    auth: AuthConfig = AuthConfig()


CASES: dict[str, Case] = {
    "default": Case(),
    "explicit_templates": Case(
        options={"templates": ["http/cves/2024/CVE-2024-0001.yaml", "dns/caa.yaml"]}
    ),
    "user_template_dirs_win": Case(
        options={"template_dirs": ["/opt/custom"], "templates": ["x.yaml"]},
        call={"template_dirs": ["http/cves"]},
    ),
    "phase_dirs_hide_templates": Case(
        options={"templates": ["x.yaml"]}, call={"template_dirs": ["http/exposures"]}
    ),
    "tags_merge_case_insensitive": Case(
        options={"tags": ["cves", "WordPress"]},
        call={"extra_tags": ["wordpress", "joomla", "JOOMLA"]},
    ),
    "workflows_exclusions_url_file": Case(
        call={
            "workflows": ["workflows/wordpress-workflow.yaml"],
            "exclude_templates": ["http/technologies", "http/exposures"],
            "automatic": True,
            "url_file": "/tmp/nuclei_urls_x.txt",
        }
    ),
    "severity_and_exclude_tags": Case(
        options={"severity": ["high", "critical"], "exclude_tags": ["intrusive"]}
    ),
    "dos_already_excluded": Case(options={"exclude_tags": ["DOS", "fuzz"]}),
    "rate_limit_static": Case(options={"rate_limit": 50}),
    "rate_limit_bound_floor": Case(rate_rps=7.5),
    "rate_limit_bound_capped": Case(options={"rate_limit": 20}, rate_rps=500.0),
    "rate_limit_bound_minimum": Case(rate_rps=0.4),
    "retries_and_pacing": Case(
        options={
            "retries": 5,
            "max_host_errors": 50,
            "concurrency": 3,
            "bulk_size": 4,
            "timeout_per_request": 12,
        }
    ),
    "interactsh_and_proxy": Case(
        options={"enable_interactsh": True}, proxy="http://127.0.0.1:3128"
    ),
    "cookie_header": Case(
        auth=AuthConfig(method="cookie", cookie_name="sid", cookie_value="s3cr3t")
    ),
    "bearer_header": Case(
        auth=AuthConfig(method="header", header_value="Bearer abc.def")
    ),
    "extra_args": Case(options={"extra_args": ["-fr", "-c", "3", "-mr", "9"]}),
    "extra_args_then_bound_rate": Case(
        options={"extra_args": ["-fr", "-rl", "1000"]}, rate_rps=30.0
    ),
}

EXPECTED: dict[str, str] = {
    "default": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos"
    ),
    "explicit_templates": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/cves/2024/CVE-2024-0001.yaml -t dns/caa.yaml -es info -etags dos"
    ),
    "user_template_dirs_win": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "/opt/custom -es info -etags dos"
    ),
    "phase_dirs_hide_templates": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -es info -etags dos"
    ),
    "tags_merge_case_insensitive": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com "
        "-tags cves,WordPress,joomla -es info -etags dos"
    ),
    "workflows_exclusions_url_file": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -list "
        "/tmp/nuclei_urls_x.txt -w workflows/wordpress-workflow.yaml -as -et "
        "http/technologies,http/exposures -es info -etags dos"
    ),
    "severity_and_exclude_tags": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -severity high,critical -etags intrusive,dos"
    ),
    "dos_already_excluded": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags DOS,fuzz"
    ),
    "rate_limit_static": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 50 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos"
    ),
    "rate_limit_bound_floor": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-ept code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -rl 7"
    ),
    "rate_limit_bound_capped": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-ept code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -rl 20"
    ),
    "rate_limit_bound_minimum": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-ept code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -rl 1"
    ),
    "retries_and_pacing": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 5 -mhe 50 -c 3 -bs 4 -timeout 12 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos"
    ),
    "interactsh_and_proxy": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-proxy http://127.0.0.1:3128 -rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -u https://example.com -t http/exposures "
        "-t http/misconfiguration -t http/vulnerabilities -t http/takeovers -t "
        "dast -es info -etags dos"
    ),
    "cookie_header": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -H 'Cookie: sid=s3cr3t'"
    ),
    "bearer_header": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -H 'Authorization: Bearer "
        "abc.def'"
    ),
    "extra_args": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-rate-limit 100 -ept "
        "code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -fr -c 3 -mr 9"
    ),
    "extra_args_then_bound_rate": (
        "nuclei -jsonl -or -ot -duc -silent -no-color -system-resolvers "
        "-tls-impersonate -fhr -retries 2 -mhe 500 -c 10 -bs 10 -timeout 30 "
        "-ept code,file,headless,dns,tcp,ssl,websocket,whois,javascript -eid "
        "http-missing-security-headers -no-interactsh -u https://example.com -t "
        "http/exposures -t http/misconfiguration -t http/vulnerabilities -t "
        "http/takeovers -t dast -es info -etags dos -fr -rl 1000 -rl 30"
    ),
}


@pytest.mark.parametrize("case_id", list(CASES))
def test_argv_matches_pre_split_output(case_id: str) -> None:
    case = CASES[case_id]
    scanner = NucleiScanner(dict(case.options))
    scanner._proxy = case.proxy
    scanner._rate_rps = case.rate_rps
    target = Target(base_url=BASE_URL, auth=case.auth)
    assert scanner._build_command(target, **case.call) == shlex.split(EXPECTED[case_id])
