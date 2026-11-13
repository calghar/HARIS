import sys

from haris.cli_handlers import _handle_non_scan_actions
from haris.cli_parser import build_parser
from haris.cli_scan import run_scan


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    from haris.agent.policy import bind_cli

    refused = bind_cli(args)
    if refused is not None:
        print("Agent mode requires --i-have-authorization.", file=sys.stderr)
        return refused

    non_scan_result = _handle_non_scan_actions(args)
    if non_scan_result is not None:
        return non_scan_result

    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
