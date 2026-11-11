# Governance

HARIS is maintained by one person. This note states how decisions are made.

## Maintainer

The maintainer is `calghar`. One person holds that role.

## Decisions

The maintainer decides.

A change to any of the following needs an issue before the patch is written:

- The finding-tier contract: `Verification.advance` and `ALLOWED_TRANSITIONS` in `src/haris/models/verification.py`.
- The agent safety rules in `src/haris/agent/` (`guardrails.py`, `policy.py`, `docker_runtime.py`) and in `docs/agent_safety.md`.
- The `/api/v1` surface: `API_V1_PREFIX` in `src/haris/auth/bearer.py` and the routers in `src/haris/web/routing.py`.

A change outside that list can open as a pull request. `CONTRIBUTING.md` states the test and style bar.

## Becoming a maintainer

The maintainer appoints a further maintainer by merging a pull request that adds that person to `.github/CODEOWNERS` and to this file.

## Releases

The maintainer owns version tags and releases. A tag `X.Y.Z` or `vX.Y.Z` runs `.github/workflows/release.yml`, which checks the tag against the project version, publishes to PyPI, pushes and signs the container image to GHCR, and opens a GitHub release from the matching `CHANGELOG.md` section.

## Conflicts

The maintainer settles a disagreement on a pull request in a comment on that request. A conduct report follows `CODE_OF_CONDUCT.md`. A vulnerability report in HARIS follows `SECURITY.md`.
