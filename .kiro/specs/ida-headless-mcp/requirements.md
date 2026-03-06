# Requirements Document

## Introduction

This document defines the requirements for an IDA Pro Headless MCP (Model Context Protocol) Server. The server wraps IDA Pro's headless analysis engine (idat/idat64) and exposes its reverse engineering capabilities as MCP tools. AI assistants and other MCP clients can use this server to load binaries, perform automated analysis, decompile functions, explore cross-references, manage types, search for patterns, and more — all without a GUI.

## Glossary

- **MCP_Server**: The Model Context Protocol server process that receives tool invocations from MCP clients and dispatches them to the IDA_Engine.
- **IDA_Engine**: The headless IDA Pro process (idat or idat64) that performs binary analysis, controlled by the MCP_Server via IDAPython scripts.
- **MCP_Client**: Any external application (AI assistant, script, IDE plugin) that connects to the MCP_Server using the Model Context Protocol.
- **IDB**: An IDA Pro database file (.idb for 32-bit, .i64 for 64-bit) that stores analysis results for a binary.
- **Hex_Rays_Decompiler**: The IDA Pro decompiler plugin that produces C-like pseudocode from disassembled binary code.
- **FLIRT**: Fast Library Identification and Recognition Technology — IDA's signature-based library function identification system.
- **Xref**: A cross-reference linking one address in a binary to another (code or data reference).
- **Segment**: A contiguous region of the binary's address space with defined attributes (name, permissions, class).
- **EA**: Effective Address — a numeric address within the binary's address space.
- **IDAPython**: The Python scripting interface embedded in IDA Pro, used to automate analysis tasks.

## Requirements

### Requirement 1: MCP Server Lifecycle

**User Story:** As an MCP_Client developer, I want the MCP_Server to start, accept connections, and shut down cleanly, so that I can integrate IDA analysis into automated workflows.

#### Acceptance Criteria

1. WHEN the MCP_Server is started with a valid configuration, THE MCP_Server SHALL begin listening for MCP_Client connections using the Model Context Protocol over stdio or SSE transport.
2. WHEN the MCP_Server receives a shutdown request, THE MCP_Server SHALL close all open IDB sessions, terminate all running IDA_Engine processes, and exit cleanly within 30 seconds.
3. THE MCP_Server SHALL expose a server information resource that reports the server version, supported IDA Pro version, available tools, and current session count.
4. WHEN the MCP_Server starts, THE MCP_Server SHALL validate that the configured IDA Pro installation path points to a valid idat or idat64 executable.
5. IF the configured IDA Pro path is invalid, THEN THE MCP_Server SHALL return a descriptive error message identifying the missing or invalid path and refuse to start.

### Requirement 2: IDA Database Management

**User Story:** As a reverse engineer, I want to open, save, and close IDA databases through the MCP_Server, so that I can manage analysis sessions programmatically.

#### Acceptance Criteria

1. WHEN an MCP_Client requests to open a binary file, THE MCP_Server SHALL launch an IDA_Engine process in headless mode, perform auto-analysis, and return a session identifier.
2. WHEN an MCP_Client requests to open a binary file and an existing IDB for that binary exists, THE MCP_Server SHALL offer the option to reuse the existing IDB or create a fresh analysis.
3. WHEN an MCP_Client requests to save the current IDB, THE MCP_Server SHALL persist all analysis state to the IDB file and confirm the save operation.
4. WHEN an MCP_Client requests to close a session, THE MCP_Server SHALL save the IDB (if requested), terminate the associated IDA_Engine process, and release all resources.
5. THE MCP_Server SHALL support opening both 32-bit and 64-bit binaries by selecting the appropriate idat or idat64 executable.
6. WHEN an MCP_Client requests to list active sessions, THE MCP_Server SHALL return the session identifier, binary file path, architecture, and analysis status for each open session.
7. IF the IDA_Engine process crashes during analysis, THEN THE MCP_Server SHALL detect the crash, clean up resources, and return an error to the MCP_Client with the failure reason.

### Requirement 3: Binary Auto-Analysis

**User Story:** As a reverse engineer, I want to trigger and monitor IDA's auto-analysis on loaded binaries, so that I can ensure analysis is complete before querying results.

#### Acceptance Criteria

1. WHEN a binary is opened, THE IDA_Engine SHALL perform auto-analysis including code detection, function creation, and type propagation.
2. WHEN an MCP_Client requests the analysis status, THE MCP_Server SHALL return whether auto-analysis is complete or still in progress.
3. WHEN auto-analysis completes, THE MCP_Server SHALL notify the MCP_Client that the binary is ready for queries.
4. WHEN an MCP_Client requests to re-analyze a specific address range, THE IDA_Engine SHALL re-run analysis on the specified range and report completion.

### Requirement 4: Function Listing and Management

**User Story:** As a reverse engineer, I want to list, inspect, and rename functions, so that I can understand and annotate the binary's code structure.

#### Acceptance Criteria

1. WHEN an MCP_Client requests a function list, THE MCP_Server SHALL return all recognized functions with their start EA, end EA, name, and size.
2. WHEN an MCP_Client requests a function list with a filter pattern, THE MCP_Server SHALL return only functions whose names match the specified pattern.
3. WHEN an MCP_Client requests details for a function at a given EA, THE MCP_Server SHALL return the function name, start EA, end EA, size, number of basic blocks, calling convention, and frame size.
4. WHEN an MCP_Client requests to rename a function at a given EA, THE MCP_Server SHALL update the function name in the IDB and confirm the rename operation.
5. IF the specified EA does not correspond to a recognized function, THEN THE MCP_Server SHALL return an error indicating no function exists at that address.
6. WHEN an MCP_Client requests to create a function at a given EA, THE IDA_Engine SHALL attempt to create a function starting at that address and return the result.
7. WHEN an MCP_Client requests to delete a function at a given EA, THE IDA_Engine SHALL remove the function definition and return the result.

### Requirement 5: Decompilation (Hex-Rays)

**User Story:** As a reverse engineer, I want to decompile functions into C-like pseudocode, so that I can understand binary logic at a higher level.

#### Acceptance Criteria

1. WHEN an MCP_Client requests decompilation of a function at a given EA, THE Hex_Rays_Decompiler SHALL produce C-like pseudocode and THE MCP_Server SHALL return the pseudocode text.
2. WHEN an MCP_Client requests decompilation with variable renaming hints, THE MCP_Server SHALL apply the suggested variable names to the decompiled output before returning the pseudocode.
3. IF the Hex_Rays_Decompiler is not available in the IDA Pro installation, THEN THE MCP_Server SHALL return an error indicating the decompiler plugin is not licensed or installed.
4. IF decompilation fails for a given function, THEN THE MCP_Server SHALL return an error with the failure reason provided by the Hex_Rays_Decompiler.
5. WHEN an MCP_Client requests decompilation of a function, THE MCP_Server SHALL include the function's address, name, and parameter types alongside the pseudocode.

### Requirement 6: Disassembly Views

**User Story:** As a reverse engineer, I want to retrieve disassembly listings for address ranges, so that I can inspect low-level instruction details.

#### Acceptance Criteria

1. WHEN an MCP_Client requests disassembly at a given EA, THE MCP_Server SHALL return the disassembly text for the instruction at that address including the mnemonic, operands, and any comments.
2. WHEN an MCP_Client requests disassembly for an address range, THE MCP_Server SHALL return the disassembly listing for all instructions within the specified range.
3. WHEN an MCP_Client requests disassembly for a named function, THE MCP_Server SHALL return the complete disassembly listing for that function from start EA to end EA.
4. THE MCP_Server SHALL include the EA, raw bytes, mnemonic, and operand text for each disassembled instruction.

### Requirement 7: Cross-References (Xrefs)

**User Story:** As a reverse engineer, I want to query cross-references to and from addresses, so that I can trace data and code flow through the binary.

#### Acceptance Criteria

1. WHEN an MCP_Client requests xrefs-to a given EA, THE MCP_Server SHALL return all cross-references that target that address, including the source EA, xref type (code/data), and source function name.
2. WHEN an MCP_Client requests xrefs-from a given EA, THE MCP_Server SHALL return all cross-references originating from that address, including the target EA, xref type, and target function name.
3. WHEN an MCP_Client requests xrefs for a named function, THE MCP_Server SHALL return all callers of and callees from that function.
4. THE MCP_Server SHALL classify each xref as one of: code call, code jump, data read, data write, or data offset.

### Requirement 8: String Extraction and Search

**User Story:** As a reverse engineer, I want to extract and search strings in the binary, so that I can identify interesting data references and functionality.

#### Acceptance Criteria

1. WHEN an MCP_Client requests all strings, THE MCP_Server SHALL return each string with its EA, value, length, and string type (ASCII, UTF-8, UTF-16, etc.).
2. WHEN an MCP_Client requests strings matching a filter pattern, THE MCP_Server SHALL return only strings whose values match the specified pattern.
3. WHEN an MCP_Client requests xrefs for a specific string, THE MCP_Server SHALL return all code locations that reference that string's EA.
4. THE MCP_Server SHALL support pagination for string results, accepting an offset and limit parameter.

### Requirement 9: Segment and Section Information

**User Story:** As a reverse engineer, I want to inspect binary segments and their attributes, so that I can understand the binary's memory layout.

#### Acceptance Criteria

1. WHEN an MCP_Client requests the segment list, THE MCP_Server SHALL return all segments with their name, start EA, end EA, size, permissions (read/write/execute), class, and bitness.
2. WHEN an MCP_Client requests details for a specific segment by name or EA, THE MCP_Server SHALL return the full attributes of that segment.
3. WHEN an MCP_Client requests the segment containing a given EA, THE MCP_Server SHALL return the segment that contains that address.

### Requirement 10: Import and Export Tables

**User Story:** As a reverse engineer, I want to list imported and exported symbols, so that I can understand the binary's external dependencies and public interface.

#### Acceptance Criteria

1. WHEN an MCP_Client requests the import list, THE MCP_Server SHALL return all imported functions grouped by library, including the function name, ordinal, and EA.
2. WHEN an MCP_Client requests the export list, THE MCP_Server SHALL return all exported symbols with their name, ordinal, and EA.
3. WHEN an MCP_Client requests imports filtered by library name, THE MCP_Server SHALL return only imports from the specified library.

### Requirement 11: Type Information and Struct Management

**User Story:** As a reverse engineer, I want to create, inspect, and modify types and structures, so that I can improve analysis accuracy and decompilation output.

#### Acceptance Criteria

1. WHEN an MCP_Client requests the local type list, THE MCP_Server SHALL return all locally defined types with their name, size, and definition.
2. WHEN an MCP_Client requests to create a new struct type, THE MCP_Server SHALL create the struct in the IDB with the specified name and fields, and confirm creation.
3. WHEN an MCP_Client requests to add a field to an existing struct, THE MCP_Server SHALL add the field at the specified offset with the given name and type.
4. WHEN an MCP_Client requests to apply a type to a function or variable at a given EA, THE IDA_Engine SHALL apply the type and THE MCP_Server SHALL confirm the operation.
5. WHEN an MCP_Client requests to delete a local type by name, THE MCP_Server SHALL remove the type from the IDB and confirm deletion.
6. WHEN an MCP_Client requests to parse a C header declaration, THE IDA_Engine SHALL parse the declaration and add the resulting types to the IDB.
7. IF a type name conflicts with an existing type, THEN THE MCP_Server SHALL return an error identifying the conflict.

### Requirement 12: Comments and Annotations

**User Story:** As a reverse engineer, I want to set and retrieve comments at addresses, so that I can annotate the binary with analysis notes.

#### Acceptance Criteria

1. WHEN an MCP_Client requests to set a regular comment at a given EA, THE MCP_Server SHALL store the comment text at that address in the IDB.
2. WHEN an MCP_Client requests to set a repeatable comment at a given EA, THE MCP_Server SHALL store the repeatable comment at that address in the IDB.
3. WHEN an MCP_Client requests to set a function comment for a function at a given EA, THE MCP_Server SHALL store the function-level comment in the IDB.
4. WHEN an MCP_Client requests comments at a given EA, THE MCP_Server SHALL return both the regular and repeatable comments at that address.
5. WHEN an MCP_Client requests all comments in a given address range, THE MCP_Server SHALL return all addresses with comments and their associated text within that range.

### Requirement 13: Patching and Byte Manipulation

**User Story:** As a reverse engineer, I want to read and write bytes in the binary, so that I can inspect raw data and apply patches.

#### Acceptance Criteria

1. WHEN an MCP_Client requests to read bytes at a given EA for a specified length, THE MCP_Server SHALL return the raw byte values as a hex string.
2. WHEN an MCP_Client requests to patch bytes at a given EA with specified values, THE IDA_Engine SHALL write the bytes to the IDB and THE MCP_Server SHALL confirm the patch.
3. WHEN an MCP_Client requests to patch a single instruction at a given EA with a new assembly string, THE IDA_Engine SHALL assemble the instruction and write the resulting bytes.
4. WHEN an MCP_Client requests the list of patched bytes, THE MCP_Server SHALL return all addresses that have been patched along with original and patched byte values.
5. IF the specified EA falls outside any defined segment, THEN THE MCP_Server SHALL return an error indicating the address is unmapped.

### Requirement 14: Search Capabilities

**User Story:** As a reverse engineer, I want to search for byte patterns, text, and immediate values in the binary, so that I can locate specific code or data.

#### Acceptance Criteria

1. WHEN an MCP_Client requests a byte pattern search with a hex pattern (supporting wildcards), THE MCP_Server SHALL return all matching EAs within the specified search range.
2. WHEN an MCP_Client requests a text search with a string value, THE MCP_Server SHALL return all EAs where the text occurs in the binary.
3. WHEN an MCP_Client requests an immediate value search, THE MCP_Server SHALL return all instruction EAs that use the specified immediate operand value.
4. THE MCP_Server SHALL support limiting search results with a maximum count parameter.
5. WHEN an MCP_Client requests a search, THE MCP_Server SHALL accept optional start EA and end EA parameters to constrain the search range.

### Requirement 15: FLIRT Signature Matching

**User Story:** As a reverse engineer, I want to apply FLIRT signatures to identify library functions, so that I can reduce manual analysis effort.

#### Acceptance Criteria

1. WHEN an MCP_Client requests to apply a FLIRT signature file, THE IDA_Engine SHALL load and apply the specified signature file to the IDB.
2. WHEN an MCP_Client requests the list of applied signatures, THE MCP_Server SHALL return the names of all currently applied FLIRT signature files.
3. WHEN an MCP_Client requests the list of available signature files, THE MCP_Server SHALL return all .sig files found in the IDA Pro signatures directory.
4. WHEN FLIRT matching identifies library functions, THE IDA_Engine SHALL rename the matched functions and THE MCP_Server SHALL return the count of newly identified functions.

### Requirement 16: Bookmarks and Marked Positions

**User Story:** As a reverse engineer, I want to manage bookmarks at addresses, so that I can track interesting locations during analysis.

#### Acceptance Criteria

1. WHEN an MCP_Client requests to add a bookmark at a given EA with a description, THE MCP_Server SHALL store the marked position in the IDB.
2. WHEN an MCP_Client requests the list of bookmarks, THE MCP_Server SHALL return all marked positions with their EA and description.
3. WHEN an MCP_Client requests to delete a bookmark at a given EA, THE MCP_Server SHALL remove the marked position from the IDB.

### Requirement 17: Script Execution

**User Story:** As a reverse engineer, I want to execute arbitrary IDAPython scripts within the IDA context, so that I can perform custom analysis tasks not covered by built-in tools.

#### Acceptance Criteria

1. WHEN an MCP_Client submits an IDAPython script as a string, THE IDA_Engine SHALL execute the script in the current IDB context and THE MCP_Server SHALL return the script's stdout output and return value.
2. WHEN an MCP_Client submits an IDAPython script file path, THE IDA_Engine SHALL execute the script file in the current IDB context and THE MCP_Server SHALL return the output.
3. IF the script raises an exception, THEN THE MCP_Server SHALL return the exception type, message, and traceback.
4. WHEN an MCP_Client submits a script, THE MCP_Server SHALL enforce a configurable execution timeout and terminate the script if the timeout is exceeded.
5. THE MCP_Server SHALL provide the script execution environment with access to the idaapi, idautils, idc, and ida_funcs modules.

### Requirement 18: Batch Analysis

**User Story:** As a reverse engineer, I want to analyze multiple binaries in batch, so that I can process large sets of samples efficiently.

#### Acceptance Criteria

1. WHEN an MCP_Client submits a batch analysis request with a list of binary file paths, THE MCP_Server SHALL queue each binary for analysis and return a batch job identifier.
2. WHEN an MCP_Client requests the status of a batch job, THE MCP_Server SHALL return the progress (number of completed, in-progress, and pending binaries) and any errors.
3. THE MCP_Server SHALL limit the number of concurrent IDA_Engine processes to a configurable maximum to manage system resources.
4. WHEN a batch job completes, THE MCP_Server SHALL provide a summary including the session identifiers for each successfully analyzed binary.

### Requirement 19: Enum Management

**User Story:** As a reverse engineer, I want to create and manage enumerations, so that I can assign meaningful names to constant values used in the binary.

#### Acceptance Criteria

1. WHEN an MCP_Client requests the enum list, THE MCP_Server SHALL return all defined enums with their name, member count, and width.
2. WHEN an MCP_Client requests to create a new enum, THE MCP_Server SHALL create the enum with the specified name and members (name-value pairs).
3. WHEN an MCP_Client requests to add a member to an existing enum, THE MCP_Server SHALL add the member with the specified name and value.
4. WHEN an MCP_Client requests to apply an enum to an operand at a given EA, THE IDA_Engine SHALL apply the enum type to the specified operand.

### Requirement 20: Global Variable and Data Inspection

**User Story:** As a reverse engineer, I want to inspect named locations and global data, so that I can understand the binary's data layout.

#### Acceptance Criteria

1. WHEN an MCP_Client requests the list of named locations (names window), THE MCP_Server SHALL return all user-defined and auto-generated names with their EA and type.
2. WHEN an MCP_Client requests to rename a location at a given EA, THE MCP_Server SHALL update the name in the IDB and confirm the operation.
3. WHEN an MCP_Client requests the data type at a given EA, THE MCP_Server SHALL return the type information (byte, word, dword, string, struct, etc.) and size.
4. WHEN an MCP_Client requests to change the data type at a given EA, THE IDA_Engine SHALL apply the new type and THE MCP_Server SHALL confirm the operation.

### Requirement 21: Call Graph and Function Relationships

**User Story:** As a reverse engineer, I want to explore call graphs, so that I can understand function relationships and program flow.

#### Acceptance Criteria

1. WHEN an MCP_Client requests the callers of a function at a given EA, THE MCP_Server SHALL return all functions that call the specified function.
2. WHEN an MCP_Client requests the callees of a function at a given EA, THE MCP_Server SHALL return all functions called by the specified function.
3. WHEN an MCP_Client requests a call graph rooted at a given function EA with a specified depth, THE MCP_Server SHALL return the call tree up to the specified depth.

### Requirement 22: Error Handling and Validation

**User Story:** As an MCP_Client developer, I want consistent and informative error responses, so that I can handle failures gracefully.

#### Acceptance Criteria

1. IF an MCP_Client provides an invalid EA (non-numeric or out of range), THEN THE MCP_Server SHALL return an error with a message identifying the invalid address.
2. IF an MCP_Client invokes a tool on a session that does not exist, THEN THE MCP_Server SHALL return an error identifying the unknown session.
3. IF an MCP_Client invokes a tool that requires an active IDB but no IDB is loaded, THEN THE MCP_Server SHALL return an error indicating no active analysis session.
4. THE MCP_Server SHALL include a consistent error structure in all error responses containing an error code, human-readable message, and the tool name that failed.
5. IF the IDA_Engine becomes unresponsive for longer than a configurable timeout, THEN THE MCP_Server SHALL terminate the IDA_Engine process and return a timeout error to the MCP_Client.
