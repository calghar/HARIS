from pydantic import BaseModel, ConfigDict


class ScanProfile(BaseModel):
    """A named, scenario-based scan configuration."""

    model_config = ConfigDict(frozen=True)

    name: str
    display_name: str
    description: str
    scanners: list[str]
    report_intro: str
    estimated_duration: str
    use_case: str

    def scanner_set(self) -> set[str]:
        return set(self.scanners)
