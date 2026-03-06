"""Session management MCP tools.

Provides tools for creating, listing, and closing IDA analysis sessions.
"""

from __future__ import annotations

from ida_headless_mcp.session_manager import SessionManager


async def create_session(
    session_manager: SessionManager,
    binary_path: str,
    reuse_idb: bool = True,
) -> dict:
    """Create a new IDA analysis session for a binary.

    Args:
        session_manager: Injected by the server.
        binary_path: Absolute path to the binary to analyse.
        reuse_idb: If True, reuse an existing IDB when available.

    Returns:
        Dict with session_id and session info.
    """
    session = await session_manager.create_session(binary_path, reuse_idb=reuse_idb)
    info = session.to_session_info()
    return {
        "session_id": info.session_id,
        "binary_path": info.binary_path,
        "idb_path": info.idb_path,
        "architecture": info.architecture,
        "state": info.state,
    }


async def list_sessions(session_manager: SessionManager) -> list[dict]:
    """List all active IDA sessions.

    Args:
        session_manager: Injected by the server.

    Returns:
        List of session info dicts.
    """
    sessions = session_manager.list_sessions()
    return [
        {
            "session_id": s.session_id,
            "binary_path": s.binary_path,
            "idb_path": s.idb_path,
            "architecture": s.architecture,
            "state": s.state,
        }
        for s in sessions
    ]


async def close_session(
    session_manager: SessionManager,
    session_id: str,
    save: bool = True,
) -> dict:
    """Close an IDA analysis session.

    Args:
        session_manager: Injected by the server.
        session_id: The session to close.
        save: Whether to save the IDB before closing.

    Returns:
        Confirmation dict.
    """
    await session_manager.close_session(session_id, save=save)
    return {"status": "closed", "session_id": session_id}
