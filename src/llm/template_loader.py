"""Loads and renders Jinja2 prompt templates."""

from pathlib import Path
from typing import Any

import jinja2

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class PromptTemplateLoader:
    """Load .j2 templates from the templates directory and render them."""

    def __init__(self, template_dir: Path | None = None) -> None:
        self._template_dir = template_dir or _TEMPLATES_DIR
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self._template_dir)),
            autoescape=False,
            undefined=jinja2.StrictUndefined,
            keep_trailing_newline=False,
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def render(self, template_path: str, **context: Any) -> str:
        """Render a template file with the given context variables."""
        template = self._env.get_template(template_path)
        return template.render(**context)


_loader = PromptTemplateLoader()


def render_template(template_path: str, **context: Any) -> str:
    """Module-level convenience for rendering a template."""
    return _loader.render(template_path, **context)
