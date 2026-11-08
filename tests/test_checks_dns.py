import pytest

from haris.checks.dns_checks import DnsRecordScanner, is_dns_name, parent_domains
from haris.checks.dns_wire import (
    CAA,
    TXT,
    DnsError,
    build_query,
    parse_answers,
    system_nameservers,
)
from haris.checks.findings import prior
from haris.models import Target

from .dns_support import LOOPBACK, Records, answer, dns_server

TARGET = Target(base_url="https://www.example.test")
COMPLETE: Records = {
    ("example.test", "CAA"): ["issue letsencrypt.org"],
    ("example.test", "TXT"): ["v=spf1 include:_spf.example.test -all"],
    ("_dmarc.example.test", "TXT"): ["v=DMARC1; p=reject"],
}


def scan(records: Records, target: Target = TARGET, servfail: set[str] | None = None):
    with dns_server(records, servfail) as (port, seen):
        scanner = DnsRecordScanner(
            {"nameservers": [LOOPBACK], "dns_port": port, "dns_timeout": 2.0}
        )
        return scanner.scan(target), seen


def test_missing_records_produce_one_finding_each_with_the_right_cwe():
    result, _ = scan({})

    by_class = {f.vuln_class: f for f in result.findings}
    assert sorted(by_class) == [
        "dns_missing_caa",
        "dns_missing_dmarc",
        "dns_missing_spf",
    ]
    assert by_class["dns_missing_caa"].cwe_id == "CWE-693"
    assert by_class["dns_missing_spf"].cwe_id == "CWE-290"
    assert by_class["dns_missing_dmarc"].confidence_score == prior(
        "dns_checks.missing_dmarc"
    )
    assert result.errors == []


def test_records_on_the_parent_domain_satisfy_all_three_checks():
    result, seen = scan(COMPLETE)

    assert result.findings == []
    assert "_dmarc.www.example.test/16" in seen
    assert "_dmarc.example.test/16" in seen


def test_records_on_the_host_itself_are_enough():
    records: Records = {
        ("www.example.test", "CAA"): ["issue ;"],
        ("www.example.test", "TXT"): ["v=spf1 -all"],
        ("_dmarc.www.example.test", "TXT"): ["v=DMARC1; p=none"],
    }
    assert scan(records)[0].findings == []


def test_unrelated_txt_records_do_not_count_as_spf_or_dmarc():
    records: Records = {
        ("example.test", "TXT"): ["google-site-verification=abc"],
        ("_dmarc.example.test", "TXT"): ["not a policy"],
    }
    result, _ = scan(records)
    assert {f.vuln_class for f in result.findings} == {
        "dns_missing_caa",
        "dns_missing_spf",
        "dns_missing_dmarc",
    }


def test_server_failure_is_an_error_not_a_missing_record():
    result, _ = scan(COMPLETE, servfail={"example.test", "www.example.test"})

    assert result.findings == []
    assert len(result.errors) == 2  # CAA and SPF query a failing name
    assert all("rcode 2" in e for e in result.errors)


def test_unreachable_nameserver_is_an_error():
    scanner = DnsRecordScanner(
        {"nameservers": [LOOPBACK], "dns_port": 9, "dns_timeout": 0.3}
    )
    result = scanner.scan(TARGET)
    assert result.findings == [] and len(result.errors) == 3


@pytest.mark.parametrize("url", ["https://127.0.0.1", "https://localhost"])
def test_ip_and_single_label_hosts_are_skipped(url):
    result, seen = scan({}, Target(base_url=url))
    assert result.findings == [] and result.errors == [] and seen == []


def test_parent_domains_stop_before_the_tld():
    assert parent_domains("a.b.example.test") == [
        "a.b.example.test",
        "b.example.test",
        "example.test",
    ]
    assert parent_domains("example.test") == ["example.test"]


def test_is_dns_name():
    assert is_dns_name("example.test")
    assert not is_dns_name("10.0.0.1") and not is_dns_name("localhost")


def test_long_txt_record_is_joined_across_chunks():
    spf = "v=spf1 " + " ".join(f"ip4:10.0.{i}.1" for i in range(60)) + " -all"
    assert len(spf) > 255
    query = build_query("example.test", TXT, 7)
    reply = answer(query, {("example.test", "TXT"): [spf]}, set())
    assert parse_answers(reply, 7, TXT) == [spf]


def test_caa_record_is_rendered_as_text():
    query = build_query("example.test", CAA, 9)
    reply = answer(query, {("example.test", "CAA"): ["issue ca.test"]}, set())
    assert parse_answers(reply, 9, CAA) == ['0 issue "ca.test"']


def test_reply_with_wrong_id_or_truncation_is_rejected():
    reply = answer(build_query("example.test", TXT, 1), {}, set())
    with pytest.raises(DnsError, match="does not match"):
        parse_answers(reply, 2, TXT)
    truncated = reply[:2] + bytes([reply[2] | 0x02]) + reply[3:]
    with pytest.raises(DnsError, match="truncated"):
        parse_answers(truncated, 1, TXT)
    with pytest.raises(DnsError, match="short"):
        parse_answers(b"\x00", 1, TXT)


def test_system_nameservers_reads_resolv_conf(tmp_path):
    conf = tmp_path / "resolv.conf"
    conf.write_text("# c\nsearch lan\nnameserver 192.0.2.1\nnameserver 192.0.2.2\n")
    assert system_nameservers(conf) == ["192.0.2.1", "192.0.2.2"]
    assert system_nameservers(tmp_path / "missing") == []
