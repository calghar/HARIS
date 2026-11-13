import re
import subprocess
import time
from pathlib import Path

import httpx
from pydantic import BaseModel, ConfigDict

COMPOSE_FILE = Path(__file__).resolve().parent / "compose.yaml"
HEALTH_POLL_SECONDS = 3.0
DVWA_SETUP_PATH = "/setup.php"
DVWA_LOGOUT_PATH = "/logout.php"
DVWA_HOME_PATH = "index.php"
DVWA_PREPARE_TIMEOUT_SECONDS = 120.0
DVWA_LOGIN_PATH = "/login.php"
DVWA_SECURITY_PATH = "/security.php"
DVWA_USER = "admin"
DVWA_PASSWORD = "password"
DVWA_SECURITY_LEVEL = "low"
DVWA_TOKEN = re.compile(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)")
WEBGOAT_REGISTER_PATH = "/WebGoat/register.mvc"
WEBGOAT_LOGIN_PATH = "/WebGoat/login"
WEBGOAT_HOME_PATH = "/WebGoat/welcome.mvc"
WEBGOAT_USER = "haris-bench"
WEBGOAT_PASSWORD = "harisbench"
LOGIN_TIMEOUT_SECONDS = 30
# Juice Shop's per-request query fan-out aborts its heap near 5500 GETs.
JUICE_NIKTO_MAX_TIME = "40s"


class Target(BaseModel):
    model_config = ConfigDict(frozen=True)

    service: str
    container_port: int
    health_path: str
    scan_path: str = ""
    profile: str | None = None
    haris_args: tuple[str, ...] = ()
    companions: tuple[str, ...] = ()
    excluded_paths: tuple[str, ...] = ()
    scanner_extra_args: dict[str, tuple[str, ...]] = {}


TARGETS = {
    "juice_shop": Target(
        service="juice_shop",
        container_port=3000,
        health_path="/rest/admin/application-version",
        scanner_extra_args={"nikto": ("-maxtime", JUICE_NIKTO_MAX_TIME)},
    ),
    "dvwa": Target(
        service="dvwa",
        container_port=80,
        health_path="/login.php",
        companions=("dvwa_db",),
        excluded_paths=(DVWA_LOGOUT_PATH, DVWA_SETUP_PATH),
    ),
    "webgoat": Target(
        service="webgoat",
        container_port=8080,
        health_path="/WebGoat/login",
        scan_path="/WebGoat",
    ),
    "spa_catchall": Target(
        service="spa_catchall", container_port=8080, health_path="/health"
    ),
    "vuln_ai_app": Target(
        service="vuln_ai_app",
        container_port=8080,
        health_path="/health",
        profile="ai-security",
        haris_args=("--ai-active", "--i-have-authorization"),
    ),
}


def compose(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def resolve_base_url(target: Target) -> str:
    published = compose("port", target.service, str(target.container_port)).stdout
    host, _, port = published.strip().rpartition(":")
    return f"http://{host}:{port}"


def wait_healthy(base_url: str, health_path: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if httpx.get(base_url + health_path, timeout=5).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        if time.monotonic() > deadline:
            raise TimeoutError(f"{base_url}{health_path} not healthy in {timeout}s")
        time.sleep(HEALTH_POLL_SECONDS)


def dvwa_form(client: httpx.Client, path: str, **fields: str) -> dict[str, str]:
    """`fields` plus the `user_token` CSRF value found on the page at `path`."""
    token = DVWA_TOKEN.search(client.get(path).text)
    return {**fields, "user_token": token.group(1)} if token else dict(fields)


def prepare_dvwa(
    base_url: str,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DVWA_PREPARE_TIMEOUT_SECONDS,
) -> None:
    """Create the DVWA database, retrying until MariaDB accepts it."""
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=base_url, timeout=30, transport=transport) as client:
        while True:
            form = dvwa_form(
                client, DVWA_SETUP_PATH, create_db="Create / Reset Database"
            )
            client.post(
                DVWA_SETUP_PATH, data=form, follow_redirects=True
            ).raise_for_status()
            probe = dvwa_form(
                client,
                DVWA_LOGIN_PATH,
                username=DVWA_USER,
                password=DVWA_PASSWORD,
                Login="Login",
            )
            login = client.post(DVWA_LOGIN_PATH, data=probe)
            if login.headers.get("location", "").endswith(DVWA_HOME_PATH):
                return
            if time.monotonic() > deadline:
                raise TimeoutError(
                    f"{base_url}: DVWA database was not created in {timeout}s"
                )
            time.sleep(HEALTH_POLL_SECONDS)


PREPARE = {"dvwa": prepare_dvwa}


def cookie_header(client: httpx.Client) -> str:
    """The client's cookies as one `Cookie` header value."""
    cookies = {cookie.name: cookie.value for cookie in client.cookies.jar}
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def login_dvwa(base_url: str, transport: httpx.BaseTransport | None = None) -> str:
    """Log in as the default admin, set the security level; returns the cookies."""
    with httpx.Client(
        base_url=base_url,
        timeout=LOGIN_TIMEOUT_SECONDS,
        follow_redirects=True,
        transport=transport,
    ) as client:
        form = dvwa_form(
            client,
            DVWA_LOGIN_PATH,
            username=DVWA_USER,
            password=DVWA_PASSWORD,
            Login="Login",
        )
        done = client.post(DVWA_LOGIN_PATH, data=form)
        done.raise_for_status()
        if done.url.path == DVWA_LOGIN_PATH:
            raise RuntimeError(
                f"{base_url}: DVWA login was rejected "
                f"(HTTP {done.status_code}, {done.url.path})"
            )
        form = dvwa_form(
            client,
            DVWA_SECURITY_PATH,
            security=DVWA_SECURITY_LEVEL,
            seclev_submit="Submit",
        )
        client.post(DVWA_SECURITY_PATH, data=form).raise_for_status()
        return cookie_header(client)


def login_webgoat(base_url: str, transport: httpx.BaseTransport | None = None) -> str:
    """Register the bench user (a repeat is harmless), log in; returns the cookies."""
    credentials = {"username": WEBGOAT_USER, "password": WEBGOAT_PASSWORD}
    with httpx.Client(
        base_url=base_url,
        timeout=LOGIN_TIMEOUT_SECONDS,
        follow_redirects=True,
        transport=transport,
    ) as client:
        client.post(
            WEBGOAT_REGISTER_PATH,
            data={
                **credentials,
                "matchingPassword": WEBGOAT_PASSWORD,
                "agree": "agree",
            },
        )
        client.post(WEBGOAT_LOGIN_PATH, data=credentials).raise_for_status()
        home = client.get(WEBGOAT_HOME_PATH)
        if home.status_code != httpx.codes.OK or home.url.path == WEBGOAT_LOGIN_PATH:
            raise RuntimeError(f"{base_url}: WebGoat login was rejected")
        return cookie_header(client)


LOGIN = {"dvwa": login_dvwa, "webgoat": login_webgoat}
