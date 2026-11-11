from ..models.templates import TemplateMetadata, UpdateResult


class TemplateUpdateReporter:
    """Formats template update results for human consumption."""

    @staticmethod
    def format_cli(results: list[UpdateResult]) -> str:
        """Format update results for terminal output."""
        if not results:
            return "No template sources configured."

        lines: list[str] = ["Template update results:", ""]
        for r in results:
            status = "OK" if r.success else "FAILED"
            line = f"  [{status}] {r.source_name} ({r.scanner})"
            if r.success:
                if r.previous_version and r.new_version:
                    line += f"  {r.previous_version} -> {r.new_version}"
                elif r.new_version:
                    line += f"  version {r.new_version}"
                line += f"  ({r.templates_added} templates)"
            else:
                line += f"  error: {r.error}"
            lines.append(line)

        ok = sum(1 for r in results if r.success)
        lines.append("")
        lines.append(f"{ok}/{len(results)} sources updated successfully.")
        return "\n".join(lines)

    @staticmethod
    def format_summary(metadata: list[TemplateMetadata]) -> str:
        """Format current template source status for display."""
        if not metadata:
            return "No template sources tracked.  Run 'update-templates' first."

        lines: list[str] = ["Template sources:", ""]
        for m in metadata:
            line = f"  {m.source_name} ({m.scanner})"
            if m.version:
                line += f"  version={m.version}"
            if m.template_count:
                line += f"  templates={m.template_count}"
            if m.last_updated:
                line += f"  updated={m.last_updated[:19]}"
            lines.append(line)

        return "\n".join(lines)
