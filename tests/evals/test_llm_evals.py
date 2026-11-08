import pytest

from tests.evals.runner import load_cases, run_case


@pytest.mark.parametrize("case", load_cases(), ids=lambda c: c["name"])
def test_eval_case(case):
    metrics = run_case(case)
    for key, want in case["expect"].items():
        if key == "statuses":
            for finding_id, status in want.items():
                assert metrics["statuses"].get(finding_id) == status
        else:
            assert metrics[key] == want, f"{key}: {metrics[key]!r} != {want!r}"
