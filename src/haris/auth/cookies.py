from fastapi import Request, Response

SESSION_COOKIE = "haris_session"
SEED_COOKIE = "haris_csrf"
SESSION_MAX_AGE = 8 * 3600
SEED_MAX_AGE = 3600


def is_https(request: Request) -> bool:
    return str(request.url.scheme) == "https"


def set_session_cookie(response: Response, token: str, *, secure: bool) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=SESSION_MAX_AGE,
        path="/",
    )


def set_seed_cookie(response: Response, seed: str, *, secure: bool) -> None:
    response.set_cookie(
        SEED_COOKIE,
        value=seed,
        httponly=True,
        samesite="lax",
        secure=secure,
        max_age=SEED_MAX_AGE,
        path="/",
    )


def clear_session_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE, SEED_COOKIE, "haris_remember"):
        response.delete_cookie(name, path="/")
