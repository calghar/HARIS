import logging
import shutil
import subprocess
import urllib.request
from pathlib import Path

logger = logging.getLogger(__name__)


class TemplateUpdater:
    """Handles git clone/pull and HTTP downloads for template sources."""

    # ------------------------------------------------------------------
    # Git operations
    # ------------------------------------------------------------------

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
        git: str, repo_url: str, target_dir: Path, branch: str,
    ) -> bool:
        target_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            git, "clone",
            "--depth", "1",
            "--branch", branch,
            "--single-branch",
            repo_url,
            str(target_dir),
        ]
        try:
            subprocess.run(
                cmd, capture_output=True, text=True, timeout=300, check=True,
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
                [git, "-C", str(target_dir), "fetch", "--depth", "1",
                 "origin", branch],
                capture_output=True, text=True, timeout=120, check=True,
            )
            subprocess.run(
                [git, "-C", str(target_dir), "reset", "--hard",
                 f"origin/{branch}"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            logger.info("Updated %s (branch %s)", target_dir, branch)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.error("git pull failed in %s: %s", target_dir, exc)
            return False

    # ------------------------------------------------------------------
    # Version tracking
    # ------------------------------------------------------------------

    @staticmethod
    def get_git_version(repo_dir: Path) -> str:
        """Return the short SHA of HEAD in a git repository."""
        git = shutil.which("git")
        if git is None or not (repo_dir / ".git").is_dir():
            return ""
        try:
            result = subprocess.run(
                [git, "-C", str(repo_dir), "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, timeout=10, check=True,
            )
            return result.stdout.strip()
        except Exception:
            return ""

    # ------------------------------------------------------------------
    # HTTP download
    # ------------------------------------------------------------------

    @staticmethod
    def download_file(url: str, target_path: Path) -> bool:
        """Download a single file via HTTP(S).

        Returns ``True`` on success, ``False`` on failure.
        """
        target_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=60) as resp:
                target_path.write_bytes(resp.read())
            logger.info("Downloaded %s -> %s", url, target_path)
            return True
        except Exception as exc:
            logger.error("Download failed for %s: %s", url, exc)
            return False

    # ------------------------------------------------------------------
    # File counting
    # ------------------------------------------------------------------

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
