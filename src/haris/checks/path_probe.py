import logging
from collections.abc import Iterable
from urllib.parse import urljoin

from pydantic import BaseModel, ConfigDict

from ..net import ScopedClient, ScopedResponse
from .baseline import PathVerdict, get_baseline
from .requesting import try_request

logger = logging.getLogger(__name__)


class PathHit(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    url: str
    response: ScopedResponse
    verdict: PathVerdict


def probe_paths(
    client: ScopedClient, base_url: str, paths: Iterable[str]
) -> list[PathHit]:
    """GET each path and return only those the soft-404 baseline accepts."""
    urls: dict[str, str] = {}
    responses: dict[str, ScopedResponse] = {}
    for path in paths:
        url = urljoin(base_url + "/", path.lstrip("/"))
        resp = try_request(client, "GET", url)
        if resp is None:
            continue
        if resp.redirect_chain:
            logger.debug("%s redirected, not the probed resource", url)
            continue
        urls[path], responses[path] = url, resp

    verdicts = get_baseline(client, base_url).judge_many(responses)
    hits: list[PathHit] = []
    for path, verdict in verdicts.items():
        if verdict.report:
            hits.append(
                PathHit(
                    path=path, url=urls[path], response=responses[path], verdict=verdict
                )
            )
        else:
            logger.debug("%s not reported: %s", urls[path], verdict.reason)
    return hits
