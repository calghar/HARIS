from .oracles import (
    OracleSpec,
    canary,
    error_signature,
    header_presence,
    open_redirect,
    path_traversal,
    reflection,
)
from .oracles_active import BOOLEAN_PER_ROUND, boolean_sqli, code_eval, file_marker
from .oracles_baseline import (
    SOFT404_COST,
    VALIDATOR_COST,
    content_validator,
    soft404,
)
from .timing import request_cost, timing, timing_cmd

DEFAULT_COST = 2

# Keys are the ``verification.oracle`` names; the value carries the request cost.
ORACLES: dict[str, OracleSpec] = {
    "reflection": OracleSpec(reflection, lambda _s: DEFAULT_COST),
    "error_signature": OracleSpec(error_signature, lambda _s: DEFAULT_COST),
    "path_traversal": OracleSpec(
        path_traversal, lambda s: DEFAULT_COST * len(s.traversal_payloads)
    ),
    "open_redirect": OracleSpec(open_redirect, lambda _s: DEFAULT_COST),
    "header_presence": OracleSpec(header_presence, lambda _s: DEFAULT_COST),
    "canary": OracleSpec(canary, lambda _s: DEFAULT_COST),
    "soft404": OracleSpec(soft404, lambda _s: SOFT404_COST),
    "content_validator": OracleSpec(content_validator, lambda _s: VALIDATOR_COST),
    "timing": OracleSpec(timing, lambda s: request_cost(s.timing, s.timing.payloads)),
    "timing_cmd": OracleSpec(
        timing_cmd, lambda s: request_cost(s.timing, s.timing.cmd_payloads)
    ),
    "file_marker": OracleSpec(file_marker, lambda s: s.file_marker_cost),
    "code_eval": OracleSpec(code_eval, lambda s: s.code_eval_cost),
    "boolean_sqli": OracleSpec(
        boolean_sqli, lambda s: s.boolean_repeats * BOOLEAN_PER_ROUND
    ),
}
