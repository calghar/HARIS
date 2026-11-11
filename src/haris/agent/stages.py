from ..models import ScanSession


def note_stage(session: ScanSession, name: str) -> None:
    session.stage_log.append(name)
