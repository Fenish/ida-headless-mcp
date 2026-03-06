# Implementation Plan: IDA Headless MCP Server

## Overview

Build a Python MCP server wrapping IDA Pro's headless engine (idat/idat64) as MCP tools. Bottom-up approach: core infrastructure, session management, tool handlers by domain, batch processing, then integration wiring.

## Tasks

- [x] 1. Project scaffolding and core infrastructure
  - [x] 1.1 Create project structure and package configuration
    - Create `pyproject.toml` with dependencies: `mcp`, `hypothesis`, `pytest`, `pytest-asyncio`
    - Create `ida_headless_mcp/` package, `ida_headless_mcp/tools/` subpackage, test directories
    - _Requirements: 1.1_
  - [x] 1.2 Implement configuration module (`ida_headless_mcp/config.py`)
    - Define `ServerConfig` dataclass with all fields from design
    - Implement `validate()` checking `ida_path` for valid `idat`/`idat64`
    - _Requirements: 1.4, 1.5_
  - [x] 1.3 Implement error types (`ida_headless_mcp/errors.py`)
    - Define `ErrorCode` string enum with all 14 error codes from design
    - Define `McpToolError` dataclass with `code`, `message`, `tool_name` fields
    - Implement `to_dict()` method for JSON serialization
    - _Requirements: 22.1, 22.2, 22.3, 22.4_

  - [x] 1.4 Implement data models (`ida_headless_mcp/models.py`)
    - Define all dataclasses from design: `SessionInfo`, `FunctionInfo`, `FunctionDetails`, `DecompileResult`, `InstructionInfo`, `XrefInfo`, `FunctionXrefs`, `StringInfo`, `StringResults`, `SegmentInfo`, `ImportInfo`, `ExportInfo`, `TypeInfo`, `FieldDef`, `CommentInfo`, `PatchInfo`, `SignatureResult`, `BookmarkInfo`, `BatchJobInfo`, `BatchStatus`, `EnumInfo`, `EnumMember`, `NameInfo`, `DataTypeInfo`, `FunctionRef`, `CallGraphNode`, `OperationResult`
    - Implement `parse_ea()` utility function with hex/decimal support and `ValueError` on invalid input
    - _Requirements: 4.1, 5.5, 6.4, 7.4, 8.1, 9.1, 10.1, 10.2, 11.1, 12.4, 13.4, 15.2, 16.2, 18.2, 19.1, 20.1, 21.1, 22.1_

  - [x] 1.5 Write property tests for EA validation and error structure
    - **Property 29: EA validation** — generate random strings (numeric/non-numeric) and verify `parse_ea` behavior
    - **Validates: Requirements 22.1**
    - **Property 30: Error response structure consistency** — generate random error scenarios and verify all fields present
    - **Validates: Requirements 22.2, 22.4**


- [x] 2. Test infrastructure and Hypothesis strategies
  - [x] 2.1 Implement test fixtures and mock IDA bridge (`tests/conftest.py`)
    - Create `MockIdaBridge` that simulates script execution with in-memory state
    - Create `MockSession` that simulates sessions without spawning IDA processes
    - Create shared pytest fixtures for mock session manager, mock bridge, sample data
    - _Requirements: all (test infrastructure)_

  - [x] 2.2 Implement Hypothesis strategies (`tests/strategies.py`)
    - Define strategies for: valid EAs (hex strings), function names, type definitions, byte patterns with wildcards, comment strings, enum names/members, file paths, address ranges, filter patterns
    - Define composite strategies for: FunctionInfo lists, XrefInfo lists, SegmentInfo lists, import/export lists, call graph trees
    - _Requirements: all (test infrastructure)_

- [x] 3. IDA Bridge and script generation
  - [x] 3.1 Implement IDA Bridge (`ida_headless_mcp/ida_bridge.py`)
    - Define `ScriptResult` dataclass with `success`, `data`, `stdout`, `stderr`, `return_value` fields
    - Implement `IdaBridge` class with `build_script(operation, params) -> str` method
    - Implement `parse_result(result_path) -> ScriptResult` method for reading JSON result files
    - Implement script template pattern: try/except wrapper, JSON result writing, `idc.qexit(0)` termination
    - Support all operations: function listing, decompilation, disassembly, xrefs, strings, segments, imports/exports, types, comments, patching, search, signatures, bookmarks, scripting, enums, data, callgraph
    - _Requirements: 17.1, 17.5_

  - [x] 3.2 Implement IDAPython command loop script (`ida_headless_mcp/scripts/command_loop.py`)
    - Implement the file-watching command loop that runs inside IDA processes
    - Read `IDA_MCP_COMMAND_DIR` from environment
    - Poll for `script.py`, execute via `exec()`, write `result.json`, create `ready` sentinel
    - Handle exceptions and write error results
    - _Requirements: 2.1, 17.1_

  - [x] 3.3 Write unit tests for IDA Bridge
    - Test script generation for each operation type produces valid Python
    - Test result parsing for success and error JSON files
    - Test script template includes proper try/except and qexit
    - _Requirements: 17.1, 17.5_


- [x] 4. Session management
  - [x] 4.1 Implement Session Manager (`ida_headless_mcp/session_manager.py`)
    - Define `SessionState` enum: `STARTING`, `ANALYZING`, `READY`, `BUSY`, `ERROR`, `CLOSED`
    - Define `Session` class with fields: `session_id`, `binary_path`, `idb_path`, `architecture`, `state`, `process`, `created_at`, `command_dir`
    - Implement `SessionManager` class with asyncio semaphore for concurrency limiting
    - Implement `create_session(binary_path, reuse_idb)`: detect architecture, select idat/idat64, spawn process, create temp command_dir, return Session
    - Implement `close_session(session_id, save)`: send save/quit command, terminate process, cleanup temp dir
    - Implement `close_all_sessions()`: close all active sessions
    - Implement `execute_script(session_id, script)`: write script to command_dir, wait for result.json, parse and return ScriptResult
    - Implement `get_session(session_id)` and `list_sessions()`
    - Implement IDB reuse detection: check for existing `.idb`/`.i64` files
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3_

  - [x] 4.2 Implement process crash detection and timeout handling
    - Monitor IDA process exit codes for unexpected termination
    - Set session state to ERROR on crash, capture stderr
    - Implement configurable timeout for unresponsive processes
    - Force-kill processes that exceed timeout
    - Clean up temp files on any failure path
    - _Requirements: 2.7, 22.5_

  - [x] 4.3 Write property tests for session lifecycle
    - **Property 2: Session lifecycle round-trip** — create sessions with random binary paths, verify unique IDs, verify list/close behavior
    - **Validates: Requirements 2.1, 2.4, 2.6**
    - **Property 3: Architecture-based executable selection** — generate random binaries with 32/64-bit markers, verify correct idat/idat64 selection
    - **Validates: Requirements 2.5**

- [x] 5. Checkpoint — Core infrastructure validation
  - Ensure all tests pass, ask the user if questions arise.


- [x] 6. Function and decompilation tool handlers
  - [x] 6.1 Implement function tools (`ida_headless_mcp/tools/functions.py`)
    - Implement `list_functions(session_id, filter_pattern)` — dispatch script, parse FunctionInfo list, apply filter
    - Implement `get_function_details(session_id, ea)` — dispatch script, parse FunctionDetails
    - Implement `rename_function(session_id, ea, new_name)` — dispatch rename script, return OperationResult
    - Implement `create_function(session_id, ea)` — dispatch create script, return OperationResult
    - Implement `delete_function(session_id, ea)` — dispatch delete script, return OperationResult
    - Validate EA input with `parse_ea()`, raise FUNCTION_NOT_FOUND for invalid function EAs
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [x] 6.2 Write property tests for function tools
    - **Property 4: Function filter correctness** — generate random function lists and filter patterns, verify inclusion/exclusion
    - **Validates: Requirements 4.2**
    - **Property 5: Function details completeness** — generate random FunctionDetails, verify all required fields and size == end_ea - start_ea
    - **Validates: Requirements 4.1, 4.3**
    - **Property 6: Function rename round-trip** — generate random function EAs and names, verify rename persists
    - **Validates: Requirements 4.4**
    - **Property 7: Function create/delete round-trip** — generate random valid EAs, verify create adds and delete removes
    - **Validates: Requirements 4.6, 4.7**

  - [x] 6.3 Implement decompilation tools (`ida_headless_mcp/tools/decompile.py`)
    - Implement `decompile_function(session_id, ea, var_hints)` — dispatch decompile script, parse DecompileResult
    - Handle variable renaming hints by injecting rename commands into the decompile script
    - Handle DECOMPILER_UNAVAILABLE and DECOMPILATION_FAILED errors
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [x] 6.4 Write property test for decompilation
    - **Property 8: Decompilation result completeness** — generate random DecompileResult instances, verify non-empty pseudocode, EA, name, parameter_types present; verify var hints appear in output
    - **Validates: Requirements 5.1, 5.2, 5.5**


- [x] 7. Disassembly and cross-reference tool handlers
  - [x] 7.1 Implement disassembly tools (`ida_headless_mcp/tools/disassembly.py`)
    - Implement `disassemble_at(session_id, ea)` — single instruction disassembly
    - Implement `disassemble_range(session_id, start_ea, end_ea)` — range-based disassembly
    - Implement `disassemble_function(session_id, function_name_or_ea)` — full function disassembly
    - Each instruction result includes EA, raw_bytes, mnemonic, operands, comment
    - _Requirements: 6.1, 6.2, 6.3, 6.4_

  - [x] 7.2 Write property test for disassembly
    - **Property 9: Disassembly instruction completeness** — generate random instruction lists and address ranges, verify all fields present and EAs within range
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4**

  - [x] 7.3 Implement cross-reference tools (`ida_headless_mcp/tools/xrefs.py`)
    - Implement `get_xrefs_to(session_id, ea)` — all xrefs targeting the EA
    - Implement `get_xrefs_from(session_id, ea)` — all xrefs originating from the EA
    - Implement `get_function_xrefs(session_id, function_name)` — callers and callees
    - Classify xrefs as: code_call, code_jump, data_read, data_write, data_offset
    - _Requirements: 7.1, 7.2, 7.3, 7.4_

  - [x] 7.4 Write property test for cross-references
    - **Property 10: Cross-reference structural validity** — generate random XrefInfo instances, verify source_ea, target_ea, xref_type fields and valid type values
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4**


- [x] 8. String, segment, and import/export tool handlers
  - [x] 8.1 Implement string tools (`ida_headless_mcp/tools/strings.py`)
    - Implement `list_strings(session_id, filter_pattern, offset, limit)` — paginated string listing with optional filter
    - Implement `get_string_xrefs(session_id, ea)` — xrefs to a string EA
    - Return StringResults with total_count, offset, limit for pagination
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [x] 8.2 Write property tests for strings and pagination
    - **Property 11: String filter correctness** — generate random string lists and filter patterns, verify filtered results match
    - **Validates: Requirements 8.1, 8.2, 8.3**
    - **Property 12: Pagination invariants** — generate random lists with offset/limit, verify at most L entries, non-overlapping pages
    - **Validates: Requirements 8.4**

  - [x] 8.3 Implement segment tools (`ida_headless_mcp/tools/segments.py`)
    - Implement `list_segments(session_id)` — all segments with full attributes
    - Implement `get_segment(session_id, name_or_ea)` — segment by name or EA
    - Implement `get_segment_at(session_id, ea)` — segment containing the given EA
    - _Requirements: 9.1, 9.2, 9.3_

  - [x] 8.4 Write property test for segments
    - **Property 13: Segment containment invariant** — generate random segments and EAs within them, verify start_ea <= ea < end_ea and consistent results by name vs EA
    - **Validates: Requirements 9.1, 9.2, 9.3**

  - [x] 8.5 Implement import/export tools (`ida_headless_mcp/tools/imports_exports.py`)
    - Implement `list_imports(session_id, library)` — all imports, optionally filtered by library
    - Implement `list_exports(session_id)` — all exports
    - _Requirements: 10.1, 10.2, 10.3_

  - [x] 8.6 Write property test for imports/exports
    - **Property 14: Import/export completeness and filtering** — generate random import/export lists, verify all fields present and library filter works
    - **Validates: Requirements 10.1, 10.2, 10.3**

- [x] 9. Checkpoint — Tool handlers part 1 validation
  - Ensure all tests pass, ask the user if questions arise.


- [x] 10. Type, comment, and patching tool handlers
  - [x] 10.1 Implement type tools (`ida_headless_mcp/tools/types.py`)
    - Implement `list_types(session_id)` — all local types
    - Implement `create_struct(session_id, name, fields)` — create struct with fields
    - Implement `add_struct_field(session_id, struct_name, field)` — add field to existing struct
    - Implement `apply_type(session_id, ea, type_str)` — apply type at EA
    - Implement `delete_type(session_id, name)` — delete local type
    - Implement `parse_header(session_id, header_text)` — parse C header declaration
    - Handle TYPE_CONFLICT errors for duplicate names
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

  - [x] 10.2 Write property tests for types
    - **Property 15: Type lifecycle round-trip** — generate random struct names and fields, verify create/list/delete/add-field behavior
    - **Validates: Requirements 11.1, 11.2, 11.3, 11.5**
    - **Property 16: Type application round-trip** — generate random type strings and EAs, verify apply then query returns applied type
    - **Validates: Requirements 11.4**

  - [x] 10.3 Implement comment tools (`ida_headless_mcp/tools/comments.py`)
    - Implement `set_comment(session_id, ea, comment, comment_type)` — set regular, repeatable, or function comment
    - Implement `get_comments(session_id, ea)` — get all comment types at EA
    - Implement `get_comments_range(session_id, start_ea, end_ea)` — all comments in range
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5_

  - [x] 10.4 Write property test for comments
    - **Property 17: Comment round-trip** — generate random EAs and comment strings, verify set/get round-trip for each comment type and range queries
    - **Validates: Requirements 12.1, 12.2, 12.3, 12.4, 12.5**

  - [x] 10.5 Implement patching tools (`ida_headless_mcp/tools/patching.py`)
    - Implement `read_bytes(session_id, ea, length)` — read raw bytes as hex string
    - Implement `patch_bytes(session_id, ea, hex_values)` — write bytes to IDB
    - Implement `assemble_and_patch(session_id, ea, assembly)` — assemble instruction and patch
    - Implement `list_patches(session_id)` — all patched addresses with original/patched values
    - Handle ADDRESS_UNMAPPED errors for EAs outside segments
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_

  - [x] 10.6 Write property test for patching
    - **Property 18: Patch round-trip** — generate random EAs and byte sequences, verify patch then read returns patched values, verify patch list correctness
    - **Validates: Requirements 13.1, 13.2, 13.4**


- [x] 11. Search, signature, and bookmark tool handlers
  - [x] 11.1 Implement search tools (`ida_headless_mcp/tools/search.py`)
    - Implement `search_bytes(session_id, pattern, start_ea, end_ea, max_results)` — byte pattern search with wildcard support
    - Implement `search_text(session_id, text, start_ea, end_ea, max_results)` — text search
    - Implement `search_immediate(session_id, value, start_ea, end_ea, max_results)` — immediate value search
    - Validate search parameters, handle INVALID_PARAMETER for bad patterns
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5_

  - [x] 11.2 Write property tests for search
    - **Property 19: Search result constraints** — generate random search params with max_results M, verify at most M entries and EAs within range
    - **Validates: Requirements 14.4, 14.5**
    - **Property 20: Byte pattern search verification** — generate random byte data and patterns, verify reading bytes at result EAs matches pattern
    - **Validates: Requirements 14.1**
    - **Property 21: Text search verification** — generate random byte data and text strings, verify reading at result EAs contains searched text
    - **Validates: Requirements 14.2**

  - [x] 11.3 Implement signature tools (`ida_headless_mcp/tools/signatures.py`)
    - Implement `apply_signature(session_id, sig_file)` — load and apply FLIRT signature
    - Implement `list_applied_signatures(session_id)` — currently applied signatures
    - Implement `list_available_signatures()` — scan signatures directory for .sig files
    - _Requirements: 15.1, 15.2, 15.3, 15.4_

  - [x] 11.4 Write property test for signatures
    - **Property 22: Signature listing consistency** — generate random directory contents with .sig files, verify available list matches directory, verify applied list after apply
    - **Validates: Requirements 15.2, 15.3**

  - [x] 11.5 Implement bookmark tools (`ida_headless_mcp/tools/bookmarks.py`)
    - Implement `add_bookmark(session_id, ea, description)` — add marked position
    - Implement `list_bookmarks(session_id)` — all bookmarks with EA and description
    - Implement `delete_bookmark(session_id, ea)` — remove marked position
    - _Requirements: 16.1, 16.2, 16.3_

  - [x] 11.6 Write property test for bookmarks
    - **Property 23: Bookmark lifecycle round-trip** — generate random EAs and descriptions, verify add/list/delete behavior
    - **Validates: Requirements 16.1, 16.2, 16.3**


- [x] 12. Scripting, batch, enum, data, and callgraph tool handlers
  - [x] 12.1 Implement scripting tools (`ida_headless_mcp/tools/scripting.py`)
    - Implement `execute_script(session_id, script, timeout)` — execute inline IDAPython script
    - Implement `execute_script_file(session_id, script_path, timeout)` — execute script from file path
    - Capture stdout, return value, and exception info (type, message, traceback)
    - Enforce configurable timeout, terminate on exceed
    - Ensure script environment has access to idaapi, idautils, idc, ida_funcs
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5_

  - [x] 12.2 Write property test for scripting
    - **Property 24: Script execution output capture** — generate random print statements and exception-raising scripts, verify stdout capture and exception fields
    - **Validates: Requirements 17.1, 17.3**

  - [x] 12.3 Implement batch tools (`ida_headless_mcp/tools/batch.py`) and Batch Manager (`ida_headless_mcp/batch_manager.py`)
    - Define `BatchJobState` enum: PENDING, IN_PROGRESS, COMPLETED, FAILED
    - Define `BatchJob` class with job_id, binary_paths, results, errors, state
    - Implement `BatchManager` with configurable concurrency limit via asyncio semaphore
    - Implement `start_batch(binary_paths)` — queue binaries, return BatchJobInfo
    - Implement `get_status(job_id)` — return BatchStatus with completed/in_progress/pending counts
    - Implement tool handlers `start_batch()` and `get_batch_status()`
    - _Requirements: 18.1, 18.2, 18.3, 18.4_

  - [x] 12.4 Write property test for batch processing
    - **Property 25: Batch job progress invariant** — generate random batch sizes and completion sequences, verify completed + in_progress + pending == N and concurrency limit respected
    - **Validates: Requirements 18.1, 18.2, 18.3, 18.4**

  - [x] 12.5 Implement enum tools (`ida_headless_mcp/tools/enums.py`)
    - Implement `list_enums(session_id)` — all enums with name, member_count, width
    - Implement `create_enum(session_id, name, members)` — create enum with members
    - Implement `add_enum_member(session_id, enum_name, member_name, value)` — add member
    - Implement `apply_enum(session_id, ea, operand, enum_name)` — apply enum to operand
    - _Requirements: 19.1, 19.2, 19.3, 19.4_

  - [x] 12.6 Write property test for enums
    - **Property 26: Enum lifecycle round-trip** — generate random enum names and members, verify create/list/add-member behavior
    - **Validates: Requirements 19.1, 19.2, 19.3**

  - [x] 12.7 Implement data/names tools (`ida_headless_mcp/tools/data.py`)
    - Implement `list_names(session_id)` — all named locations with EA, name, type
    - Implement `rename_location(session_id, ea, new_name)` — rename location
    - Implement `get_data_type(session_id, ea)` — get type info at EA
    - Implement `set_data_type(session_id, ea, type_str)` — change data type
    - _Requirements: 20.1, 20.2, 20.3, 20.4_

  - [x] 12.8 Write property test for data/names
    - **Property 27: Name and data type round-trip** — generate random EAs, names, and type strings, verify rename and type change round-trips
    - **Validates: Requirements 20.1, 20.2, 20.3, 20.4**

  - [x] 12.9 Implement call graph tools (`ida_headless_mcp/tools/callgraph.py`)
    - Implement `get_callers(session_id, ea)` — all functions calling the target
    - Implement `get_callees(session_id, ea)` — all functions called by the target
    - Implement `get_call_graph(session_id, ea, depth)` — recursive call tree up to depth D
    - Each node contains ea and name fields
    - _Requirements: 21.1, 21.2, 21.3_

  - [x] 12.10 Write property test for call graph
    - **Property 28: Call graph depth invariant** — generate random call graphs and depth values, verify no path exceeds D edges and all nodes have ea/name
    - **Validates: Requirements 21.1, 21.2, 21.3**


- [x] 13. Checkpoint — All tool handlers validation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 14. MCP server wiring and tool registration
  - [x] 14.1 Implement MCP server entry point (`ida_headless_mcp/server.py`)
    - Define `IdaMcpServer` class with `__init__(config)` that creates SessionManager, BatchManager, and McpServer instances
    - Implement `_register_tools()` — register all tool handlers from all 15 tool modules with the MCP SDK
    - Implement `run(transport)` — start server on stdio or SSE transport
    - Validate IDA path on startup, refuse to start with descriptive error if invalid
    - Expose server info resource: version, supported IDA version, available tools, session count
    - _Requirements: 1.1, 1.3, 1.4, 1.5_

  - [x] 14.2 Implement graceful shutdown
    - Stop accepting new requests on shutdown signal
    - Cancel in-progress batch jobs
    - Send save+quit to all active IDA processes
    - Wait up to 30 seconds for graceful termination
    - Force-kill remaining processes, clean up temp dirs
    - _Requirements: 1.2_

  - [x] 14.3 Write property test for IDA path validation
    - **Property 1: IDA path validation** — generate random file paths, verify server accepts valid paths and rejects invalid ones with descriptive error
    - **Validates: Requirements 1.4, 1.5**

- [x] 15. CLI entry point and final integration
  - [x] 15.1 Create CLI entry point (`ida_headless_mcp/__main__.py`)
    - Parse command-line arguments: `--ida-path`, `--transport`, `--sse-host`, `--sse-port`, `--max-sessions`, `--signatures-dir`
    - Build ServerConfig from arguments and environment
    - Instantiate and run IdaMcpServer
    - _Requirements: 1.1_

  - [x] 15.2 Write integration test stubs (`tests/integration/`)
    - Create `test_ida_process.py` stub for real IDA process tests (gated behind `--run-integration`)
    - Create `test_end_to_end.py` stub for full MCP client-server round-trip tests
    - _Requirements: all (integration testing)_

- [x] 16. Final checkpoint — Full integration validation
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after each major phase
- Property tests validate universal correctness properties from the design document (Properties 1–30)
- Unit tests validate specific examples and edge cases
- Integration tests require a real IDA Pro installation and are gated behind `--run-integration`
- All code is Python, using asyncio for concurrency and Hypothesis for property-based testing
