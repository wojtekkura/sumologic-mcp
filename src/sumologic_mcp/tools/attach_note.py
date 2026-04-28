from sumologic_mcp.clients import state


def attach_note(
    incident_id: int,
    text: str,
    title: str = "inVestiGator Investigation",
    author: str | None = None,
) -> dict:
    """Attach a markdown note to a Sumo Logic Cloud SOAR incident.

    The body is rendered to HTML server-side (tables, fenced code).
    Author defaults to ANALYST_USERNAME from env.

    Args:
        incident_id: Numeric SOAR incident ID.
        text: Markdown body of the note.
        title: Note title.
        author: Override the author username; defaults to env ANALYST_USERNAME.

    Returns:
        {"note_id": int, "author": str}
    """
    final_author = author if author else state.creds().analyst_username
    result = state.soar().add_note(incident_id, text, title=title, author=final_author)
    return {"note_id": result.get("id"), "author": final_author}
