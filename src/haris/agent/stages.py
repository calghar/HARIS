def note_stage(session: object, name: str) -> None:
    """Append *name* to the session stage log (a private list, report order)."""
    log = getattr(session, "_stage_log", None)
    if not isinstance(log, list):
        log = []
        object.__setattr__(session, "_stage_log", log)
    log.append(name)


def stage_log(session: object) -> list[str]:
    log = getattr(session, "_stage_log", None)
    return (
        [item for item in log if isinstance(item, str)] if isinstance(log, list) else []
    )
