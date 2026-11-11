import logging
import os
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, BinaryIO
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

MAX_TEMPLATE_DOWNLOAD_BYTES = 50 * 1024 * 1024
_DOWNLOAD_CHUNK_BYTES = 64 * 1024
_DOWNLOAD_TIMEOUT_S = 60
_DOWNLOAD_SCHEMES = frozenset({"http", "https"})


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if urlsplit(newurl).scheme not in _DOWNLOAD_SCHEMES:
            raise urllib.error.URLError("redirect scheme is not http or https")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if not isinstance(redirected, urllib.request.Request):
            return None
        return redirected


def _temporary_file(target_path: Path) -> Path:
    descriptor, raw_name = tempfile.mkstemp(
        dir=target_path.parent, prefix=".", suffix=".partial"
    )
    os.close(descriptor)
    return Path(raw_name)


def _stream_capped(source: BinaryIO, path: Path, limit: int) -> None:
    total = 0
    with path.open("wb") as handle:
        while True:
            chunk = source.read(_DOWNLOAD_CHUNK_BYTES)
            if not chunk:
                return
            total += len(chunk)
            if total > limit:
                raise OSError(f"download exceeds {limit} bytes")
            handle.write(chunk)


class TemplateUpdater:
    """Handles git clone/pull and HTTP downloads for template sources."""

    @staticmethod
    def git_clone_or_pull(
        repo_url: str,
        target_dir: Path,
        branch: str = "main",
    ) -> bool:
        """Clone *repo_url* into *target_dir*, or pull if already cloned.

        Returns ``True`` on success, ``False`` on failure.
        """
        git = shutil.which("git")
        if git is None:
            logger.error("git is not installed or not on PATH")
            return False

        if (target_dir / ".git").is_dir():
            return TemplateUpdater._git_pull(git, target_dir, branch)
        return TemplateUpdater._git_clone(git, repo_url, target_dir, branch)

    @staticmethod
    def _git_clone(
        git: str,
        repo_url: str,
        target_dir: Path,
        branch: str,
    ) -> bool:
        target_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            git,
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            "--single-branch",
            repo_url,
            str(target_dir),
        ]
        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=True,
            )
            logger.info("Cloned %s -> %s", repo_url, target_dir)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.error("git clone failed for %s: %s", repo_url, exc)
            return False

    @staticmethod
    def _git_pull(git: str, target_dir: Path, branch: str) -> bool:
        try:
            subprocess.run(
                [git, "-C", str(target_dir), "fetch", "--depth", "1", "origin", branch],
                capture_output=True,
                text=True,
                timeout=120,
                check=True,
            )
            subprocess.run(
                [git, "-C", str(target_dir), "reset", "--hard", f"origin/{branch}"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
            )
            logger.info("Updated %s (branch %s)", target_dir, branch)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.error("git pull failed in %s: %s", target_dir, exc)
            return False

    # Version tracking

    @staticmethod
    def get_git_version(repo_dir: Path) -> str:
        """Return the short SHA of HEAD in a git repository."""
        git = shutil.which("git")
        if git is None or not (repo_dir / ".git").is_dir():
            return ""
        try:
            result = subprocess.run(
                [git, "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""

    # HTTP download

    @staticmethod
    def download_file(url: str, target_path: Path) -> bool:
        """Stream an http(s) file to *target_path* with a byte cap. False on failure."""
        if urlsplit(url).scheme not in _DOWNLOAD_SCHEMES:
            logger.error(
                "Download refused for %s: only http and https are allowed", url
            )
            return False
        target_path.parent.mkdir(parents=True, exist_ok=True)
        temporary: Path | None = None
        try:
            request = urllib.request.Request(url)
            opener = urllib.request.build_opener(_HttpsOnlyRedirect)
            with opener.open(request, timeout=_DOWNLOAD_TIMEOUT_S) as resp:  # nosec B310
                temporary = _temporary_file(target_path)
                _stream_capped(resp, temporary, MAX_TEMPLATE_DOWNLOAD_BYTES)
            os.replace(temporary, target_path)
            temporary = None
            logger.info("Downloaded %s -> %s", url, target_path)
            return True
        except Exception as exc:
            logger.error("Download failed for %s: %s", url, exc)
            return False
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    # File counting

    @staticmethod
    def count_files(directory: Path, patterns: list[str]) -> int:
        """Count files matching any of the given glob patterns."""
        if not directory.is_dir():
            return 0
        count = 0
        seen: set[Path] = set()
        for pattern in patterns:
            for p in directory.rglob(pattern):
                if p.is_file() and p not in seen:
                    seen.add(p)
                    count += 1
        return count
