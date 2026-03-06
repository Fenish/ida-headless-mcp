"""MCP server entry point for IDA Headless MCP.

Defines :class:`IdaMcpServer` which wires together the session manager,
batch manager, IDA bridge, and all tool handlers into a single MCP server
instance.

Requirements: 1.1, 1.3, 1.4, 1.5
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from typing import Any

from ida_headless_mcp.batch_manager import BatchManager
from ida_headless_mcp.config import ServerConfig
from ida_headless_mcp.errors import McpToolError
from ida_headless_mcp.ida_bridge import IdaBridge
from ida_headless_mcp.session_manager import SessionManager
from ida_headless_mcp.tools import (
    batch,
    bookmarks,
    callgraph,
    comments,
    data,
    decompile,
    disassembly,
    enums,
    functions,
    imports_exports,
    patching,
    scripting,
    search,
    segments,
    sessions,
    signatures,
    strings,
    types,
    xrefs,
)

__version__ = "0.1.0"
_SUPPORTED_IDA_VERSION = "8.x"

logger = logging.getLogger(__name__)


class IdaMcpServer:
    """Main server class that wires together all components.

    Args:
        config: A validated :class:`ServerConfig` instance.

    Raises:
        ValueError: If *config* fails validation (invalid IDA path, etc.).
    """

    def __init__(self, config: ServerConfig) -> None:
        config.validate()
        self.config = config
        self.session_manager = SessionManager(config)
        self.bridge = IdaBridge()
        self.batch_manager = BatchManager(
            self.session_manager, config.batch_max_concurrent
        )
        self._tools: dict[str, dict[str, Any]] = {}
        self._shutting_down: bool = False
        self._register_tools()

    # ------------------------------------------------------------------
    # Tool registration
    # ------------------------------------------------------------------

    def _register_tools(self) -> None:
        """Build the internal tool registry.

        Each entry maps a tool name to a dict with ``handler``,
        ``description``, and ``module`` keys.  This registry is used both
        for MCP SDK integration and for the server info resource.
        """

        # -- Sessions (tools/sessions.py) --
        self._tools["create_session"] = {
            "handler": sessions.create_session,
            "description": "Create a new IDA analysis session for a binary file.",
            "module": "sessions",
        }
        self._tools["list_sessions"] = {
            "handler": sessions.list_sessions,
            "description": "List all active IDA analysis sessions.",
            "module": "sessions",
        }
        self._tools["close_session"] = {
            "handler": sessions.close_session,
            "description": "Close an IDA analysis session.",
            "module": "sessions",
        }

        # -- Functions (tools/functions.py) --
        self._tools["list_functions"] = {
            "handler": functions.list_functions,
            "description": "List all recognised functions, optionally filtered by name pattern.",
            "module": "functions",
        }
        self._tools["get_function_details"] = {
            "handler": functions.get_function_details,
            "description": "Get detailed information about a function at the given EA.",
            "module": "functions",
        }
        self._tools["rename_function"] = {
            "handler": functions.rename_function,
            "description": "Rename a function at the given EA.",
            "module": "functions",
        }
        self._tools["create_function"] = {
            "handler": functions.create_function,
            "description": "Create a new function at the given EA.",
            "module": "functions",
        }
        self._tools["delete_function"] = {
            "handler": functions.delete_function,
            "description": "Delete the function at the given EA.",
            "module": "functions",
        }

        # -- Decompilation (tools/decompile.py) --
        self._tools["decompile_function"] = {
            "handler": decompile.decompile_function,
            "description": "Decompile a function at the given EA into C-like pseudocode.",
            "module": "decompile",
        }

        # -- Disassembly (tools/disassembly.py) --
        self._tools["disassemble_at"] = {
            "handler": disassembly.disassemble_at,
            "description": "Disassemble a single instruction at the given EA.",
            "module": "disassembly",
        }
        self._tools["disassemble_range"] = {
            "handler": disassembly.disassemble_range,
            "description": "Disassemble all instructions in an address range.",
            "module": "disassembly",
        }
        self._tools["disassemble_function"] = {
            "handler": disassembly.disassemble_function,
            "description": "Disassemble all instructions in a function.",
            "module": "disassembly",
        }

        # -- Cross-references (tools/xrefs.py) --
        self._tools["get_xrefs_to"] = {
            "handler": xrefs.get_xrefs_to,
            "description": "Get all cross-references targeting the given EA.",
            "module": "xrefs",
        }
        self._tools["get_xrefs_from"] = {
            "handler": xrefs.get_xrefs_from,
            "description": "Get all cross-references originating from the given EA.",
            "module": "xrefs",
        }
        self._tools["get_function_xrefs"] = {
            "handler": xrefs.get_function_xrefs,
            "description": "Get callers and callees for a named function.",
            "module": "xrefs",
        }

        # -- Strings (tools/strings.py) --
        self._tools["list_strings"] = {
            "handler": strings.list_strings,
            "description": "List strings in the binary with optional filtering and pagination.",
            "module": "strings",
        }
        self._tools["get_string_xrefs"] = {
            "handler": strings.get_string_xrefs,
            "description": "Get all cross-references to a string at the given EA.",
            "module": "strings",
        }

        # -- Segments (tools/segments.py) --
        self._tools["list_segments"] = {
            "handler": segments.list_segments,
            "description": "List all segments in the binary.",
            "module": "segments",
        }
        self._tools["get_segment"] = {
            "handler": segments.get_segment,
            "description": "Get a segment by name or EA.",
            "module": "segments",
        }
        self._tools["get_segment_at"] = {
            "handler": segments.get_segment_at,
            "description": "Get the segment containing the given EA.",
            "module": "segments",
        }

        # -- Imports / Exports (tools/imports_exports.py) --
        self._tools["list_imports"] = {
            "handler": imports_exports.list_imports,
            "description": "List all imported functions, optionally filtered by library.",
            "module": "imports_exports",
        }
        self._tools["list_exports"] = {
            "handler": imports_exports.list_exports,
            "description": "List all exported symbols.",
            "module": "imports_exports",
        }

        # -- Types (tools/types.py) --
        self._tools["list_types"] = {
            "handler": types.list_types,
            "description": "List all locally defined types.",
            "module": "types",
        }
        self._tools["create_struct"] = {
            "handler": types.create_struct,
            "description": "Create a new struct type with the given name and fields.",
            "module": "types",
        }
        self._tools["add_struct_field"] = {
            "handler": types.add_struct_field,
            "description": "Add a field to an existing struct.",
            "module": "types",
        }
        self._tools["apply_type"] = {
            "handler": types.apply_type,
            "description": "Apply a type to a function or variable at the given EA.",
            "module": "types",
        }
        self._tools["delete_type"] = {
            "handler": types.delete_type,
            "description": "Delete a local type by name.",
            "module": "types",
        }
        self._tools["parse_header"] = {
            "handler": types.parse_header,
            "description": "Parse a C header declaration and add resulting types.",
            "module": "types",
        }

        # -- Comments (tools/comments.py) --
        self._tools["set_comment"] = {
            "handler": comments.set_comment,
            "description": "Set a comment at the given EA.",
            "module": "comments",
        }
        self._tools["get_comments"] = {
            "handler": comments.get_comments,
            "description": "Get all comment types at the given EA.",
            "module": "comments",
        }
        self._tools["get_comments_range"] = {
            "handler": comments.get_comments_range,
            "description": "Get all comments within an address range.",
            "module": "comments",
        }

        # -- Patching (tools/patching.py) --
        self._tools["read_bytes"] = {
            "handler": patching.read_bytes,
            "description": "Read raw bytes at the given EA as a hex string.",
            "module": "patching",
        }
        self._tools["patch_bytes"] = {
            "handler": patching.patch_bytes,
            "description": "Write bytes to the IDB at the given EA.",
            "module": "patching",
        }
        self._tools["assemble_and_patch"] = {
            "handler": patching.assemble_and_patch,
            "description": "Assemble an instruction and patch it at the given EA.",
            "module": "patching",
        }
        self._tools["list_patches"] = {
            "handler": patching.list_patches,
            "description": "List all patched addresses with original and patched values.",
            "module": "patching",
        }

        # -- Search (tools/search.py) --
        self._tools["search_bytes"] = {
            "handler": search.search_bytes,
            "description": "Search for a byte pattern with wildcard support.",
            "module": "search",
        }
        self._tools["search_text"] = {
            "handler": search.search_text,
            "description": "Search for a text string in the binary.",
            "module": "search",
        }
        self._tools["search_immediate"] = {
            "handler": search.search_immediate,
            "description": "Search for an immediate operand value in instructions.",
            "module": "search",
        }

        # -- Signatures (tools/signatures.py) --
        self._tools["apply_signature"] = {
            "handler": signatures.apply_signature,
            "description": "Apply a FLIRT signature file to the current IDB.",
            "module": "signatures",
        }
        self._tools["list_applied_signatures"] = {
            "handler": signatures.list_applied_signatures,
            "description": "List currently applied FLIRT signatures.",
            "module": "signatures",
        }
        self._tools["list_available_signatures"] = {
            "handler": signatures.list_available_signatures,
            "description": "List available .sig files in the signatures directory.",
            "module": "signatures",
        }

        # -- Bookmarks (tools/bookmarks.py) --
        self._tools["add_bookmark"] = {
            "handler": bookmarks.add_bookmark,
            "description": "Add a bookmark at the given EA.",
            "module": "bookmarks",
        }
        self._tools["list_bookmarks"] = {
            "handler": bookmarks.list_bookmarks,
            "description": "List all bookmarks in the current IDB.",
            "module": "bookmarks",
        }
        self._tools["delete_bookmark"] = {
            "handler": bookmarks.delete_bookmark,
            "description": "Delete a bookmark at the given EA.",
            "module": "bookmarks",
        }

        # -- Scripting (tools/scripting.py) --
        self._tools["execute_script"] = {
            "handler": scripting.execute_script,
            "description": "Execute an inline IDAPython script.",
            "module": "scripting",
        }
        self._tools["execute_script_file"] = {
            "handler": scripting.execute_script_file,
            "description": "Execute an IDAPython script from a file path.",
            "module": "scripting",
        }

        # -- Batch (tools/batch.py) --
        self._tools["start_batch"] = {
            "handler": batch.start_batch,
            "description": "Start a batch analysis job for multiple binaries.",
            "module": "batch",
        }
        self._tools["get_batch_status"] = {
            "handler": batch.get_batch_status,
            "description": "Get the status of a batch analysis job.",
            "module": "batch",
        }

        # -- Enums (tools/enums.py) --
        self._tools["list_enums"] = {
            "handler": enums.list_enums,
            "description": "List all defined enums.",
            "module": "enums",
        }
        self._tools["create_enum"] = {
            "handler": enums.create_enum,
            "description": "Create a new enum with the given name and members.",
            "module": "enums",
        }
        self._tools["add_enum_member"] = {
            "handler": enums.add_enum_member,
            "description": "Add a member to an existing enum.",
            "module": "enums",
        }
        self._tools["apply_enum"] = {
            "handler": enums.apply_enum,
            "description": "Apply an enum to an operand at the given EA.",
            "module": "enums",
        }

        # -- Data / Names (tools/data.py) --
        self._tools["list_names"] = {
            "handler": data.list_names,
            "description": "List all named locations.",
            "module": "data",
        }
        self._tools["rename_location"] = {
            "handler": data.rename_location,
            "description": "Rename a location at the given EA.",
            "module": "data",
        }
        self._tools["get_data_type"] = {
            "handler": data.get_data_type,
            "description": "Get data type information at the given EA.",
            "module": "data",
        }
        self._tools["set_data_type"] = {
            "handler": data.set_data_type,
            "description": "Change the data type at the given EA.",
            "module": "data",
        }

        # -- Call Graph (tools/callgraph.py) --
        self._tools["get_callers"] = {
            "handler": callgraph.get_callers,
            "description": "Return all functions that call the function at the given EA.",
            "module": "callgraph",
        }
        self._tools["get_callees"] = {
            "handler": callgraph.get_callees,
            "description": "Return all functions called by the function at the given EA.",
            "module": "callgraph",
        }
        self._tools["get_call_graph"] = {
            "handler": callgraph.get_call_graph,
            "description": "Return a recursive call tree rooted at the given function.",
            "module": "callgraph",
        }

    # ------------------------------------------------------------------
    # Server info
    # ------------------------------------------------------------------

    def get_server_info(self) -> dict[str, Any]:
        """Return server metadata as a dict.

        Includes version, supported IDA version, available tool names,
        and current session count.
        """
        return {
            "version": __version__,
            "supported_ida_version": _SUPPORTED_IDA_VERSION,
            "available_tools": sorted(self._tools.keys()),
            "session_count": len(self.session_manager.list_sessions()),
        }

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    _GRACEFUL_TIMEOUT: int = 30

    async def shutdown(self) -> None:
        """Perform a graceful shutdown of the server.

        1. Set the ``_shutting_down`` flag to stop accepting new requests.
        2. Cancel all in-progress batch jobs.
        3. Close all active IDA sessions (save + quit).
        4. Wait up to 30 seconds for graceful termination.
        5. Force-kill remaining processes and clean up temp dirs.

        Requirements: 1.2
        """
        if self._shutting_down:
            return
        self._shutting_down = True
        logger.info("Shutdown initiated — stopping new requests")

        # 1. Cancel in-progress batch jobs
        for job_id, job in list(self.batch_manager._jobs.items()):
            if job.state.value in ("pending", "in_progress"):
                try:
                    await self.batch_manager.cancel_job(job_id)
                except Exception:
                    logger.warning("Failed to cancel batch job %s", job_id)

        # 2. Close all active sessions (save + quit) with a timeout
        try:
            await asyncio.wait_for(
                self.session_manager.close_all_sessions(),
                timeout=self._GRACEFUL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Graceful session shutdown timed out after %ds — "
                "force-killing remaining processes",
                self._GRACEFUL_TIMEOUT,
            )
            # Force-kill any remaining IDA processes and clean up
            for session in list(self.session_manager._sessions.values()):
                if session.process and session.process.returncode is None:
                    try:
                        session.process.kill()
                        await session.process.wait()
                    except Exception:
                        pass
                self.session_manager._cleanup_command_dir(session)
            self.session_manager._sessions.clear()
        except Exception:
            logger.exception("Error during session shutdown")

        logger.info("Shutdown complete")

    # ------------------------------------------------------------------
    # Run
    # ------------------------------------------------------------------

    async def run(self, transport: str | None = None) -> None:
        """Start the MCP server on the configured transport.

        Args:
            transport: Override the transport from config (``"stdio"`` or
                ``"sse"``).  Defaults to ``self.config.transport``.

        This method attempts to import the ``mcp`` SDK at runtime.  If the
        SDK is not installed the server logs an error and returns.
        """
        transport = transport or self.config.transport

        # Install signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(
                    sig,
                    lambda: asyncio.ensure_future(self.shutdown()),
                )
            except NotImplementedError:
                # Windows doesn't support add_signal_handler for all signals
                pass

        try:
            from mcp.server import Server as McpSdkServer  # type: ignore[import-untyped]
        except ImportError:
            logger.error(
                "The 'mcp' package is not installed. "
                "Install it with: pip install mcp"
            )
            raise RuntimeError(
                "The 'mcp' package is required to run the server. "
                "Install it with: pip install mcp"
            )

        from mcp.types import Tool, TextContent  # type: ignore[import-untyped]

        mcp_server = McpSdkServer("ida-headless-mcp")

        # Capture self for closures
        server_ref = self
        tools_registry = self._tools

        @mcp_server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            import inspect
            # Internal params injected by call_tool, not user-facing
            _injected = {"session_manager", "bridge", "batch_manager"}
            result = []
            for name, info in tools_registry.items():
                sig = inspect.signature(info["handler"])
                properties = {}
                required = []
                for pname, param in sig.parameters.items():
                    if pname in _injected:
                        continue
                    # Infer JSON schema type from annotation or default
                    annotation = param.annotation
                    if annotation is bool or (param.default is not inspect.Parameter.empty and isinstance(param.default, bool)):
                        ptype = "boolean"
                    elif annotation is int:
                        ptype = "integer"
                    else:
                        ptype = "string"
                    properties[pname] = {"type": ptype}
                    if param.default is inspect.Parameter.empty:
                        required.append(pname)
                schema = {"type": "object", "properties": properties}
                if required:
                    schema["required"] = required
                result.append(Tool(name=name, description=info["description"], inputSchema=schema))
            return result

        @mcp_server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
            if name not in tools_registry:
                return [TextContent(type="text", text=f"Unknown tool: {name}")]
            handler = tools_registry[name]["handler"]
            try:
                # Inject server internals based on handler signature
                import inspect
                sig = inspect.signature(handler)
                params = list(sig.parameters.keys())
                kwargs = dict(arguments) if arguments else {}

                # Inject session_manager, bridge, batch_manager as needed
                if "session_manager" in params and "session_manager" not in kwargs:
                    kwargs["session_manager"] = server_ref.session_manager
                if "bridge" in params and "bridge" not in kwargs:
                    kwargs["bridge"] = server_ref.bridge
                if "batch_manager" in params and "batch_manager" not in kwargs:
                    kwargs["batch_manager"] = server_ref.batch_manager

                result = await handler(**kwargs)
                import json as _json
                if isinstance(result, list):
                    from dataclasses import asdict
                    items = []
                    for item in result:
                        if hasattr(item, "__dataclass_fields__"):
                            items.append(asdict(item))
                        else:
                            items.append(item)
                    text = _json.dumps(items, default=str)
                elif hasattr(result, "__dataclass_fields__"):
                    from dataclasses import asdict
                    text = _json.dumps(asdict(result), default=str)
                elif isinstance(result, dict):
                    text = _json.dumps(result, default=str)
                else:
                    text = str(result)
                return [TextContent(type="text", text=text)]
            except McpToolError as exc:
                import json as _json
                return [TextContent(type="text", text=_json.dumps(exc.to_dict()))]
            except Exception as exc:
                return [TextContent(type="text", text=f"Error: {exc}")]

        try:
            if transport == "stdio":
                from mcp.server.stdio import stdio_server  # type: ignore[import-untyped]

                async with stdio_server() as (read_stream, write_stream):
                    await mcp_server.run(read_stream, write_stream, mcp_server.create_initialization_options())
            elif transport == "sse":
                from mcp.server.sse import SseServerTransport  # type: ignore[import-untyped]

                sse = SseServerTransport("/messages")
                logger.info(
                    "Starting SSE server on %s:%d",
                    self.config.sse_host,
                    self.config.sse_port,
                )
                # SSE transport integration would go here — depends on the
                # specific MCP SDK version and web framework in use.
                raise NotImplementedError(
                    f"SSE transport not yet implemented. Use stdio."
                )
            else:
                raise ValueError(f"Unknown transport: {transport!r}")
        finally:
            await self.shutdown()
