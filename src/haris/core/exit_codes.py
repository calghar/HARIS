from ..models import ScanSession, ScanState, Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INCOMPLETE = 2
EXIT_USAGE = 3

_UNFINISHED = frozenset({ScanState.INCOMPLETE, ScanState.FAILED, ScanState.CANCELLED})


def exit_code(session: ScanSession, fail_on: Severity | None) -> int:
    """Scan exit code: 2 for an unfinished scan, 1 for findings at ``fail_on``.

    Refuted and suppressed findings never count; without ``fail_on`` the code
    is never 1.  Usage errors (3) are decided before a scan exists.
    """
    if session.scan_state in _UNFINISHED:
        return EXIT_INCOMPLETE
    if fail_on is not None and any(
        c.canonical.is_active and c.canonical.severity.sort_key <= fail_on.sort_key
        for c in session.correlated
    ):
        return EXIT_FINDINGS
    return EXIT_OK
