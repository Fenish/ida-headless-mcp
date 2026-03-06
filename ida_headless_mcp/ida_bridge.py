"""IDA Bridge — script generation and result parsing for IDA headless communication.

This module is the translation layer between high-level MCP tool operations
and IDA Pro's IDAPython API.  :class:`IdaBridge` generates self-contained
IDAPython scripts that follow a consistent template pattern (try/except
wrapper, JSON result writing, ``idc.qexit(0)`` termination) and parses the
JSON result files that those scripts produce.

The bridge uses a file-based protocol: scripts are written to a session's
command directory and results are read back from JSON files.
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# ScriptResult
# ---------------------------------------------------------------------------

@dataclass
class ScriptResult:
    """Result of executing an IDAPython script.

    Attributes:
        success: Whether the script completed without error.
        data: Parsed JSON payload returned by the script.
        stdout: Captured standard output from the script.
        stderr: Captured standard error from the script.
        return_value: Optional return value from the script.
    """

    success: bool
    data: Any = None
    stdout: str = ""
    stderr: str = ""
    return_value: Any = None


# ---------------------------------------------------------------------------
# Script template helpers
# ---------------------------------------------------------------------------

_SCRIPT_HEADER = textwrap.dedent("""\
    import json
    import idaapi
    import idautils
    import idc
    import ida_funcs
    import ida_bytes
    import ida_nalt
    import ida_name
    import ida_struct
    import ida_enum
    import ida_typeinf
    import ida_hexrays
    import ida_search
    import ida_segment
    import ida_entry
    import ida_lines
""")


def _wrap_script(body: str, result_path: str) -> str:
    """Wrap an operation body in the standard IDAPython template.

    The template:
    1. Imports all required IDA modules.
    2. Defines ``RESULT_PATH`` for the JSON output file.
    3. Runs *body* inside a ``try/except`` in ``main()``.
    4. Writes the result dict to *result_path* as JSON.
    5. Calls ``idc.qexit(0)`` to terminate the IDA process.
    """
    return (
        _SCRIPT_HEADER
        + f'\nRESULT_PATH = {result_path!r}\n\n'
        + textwrap.dedent("""\
            def main():
                result = {}
                try:
            """)
        + textwrap.indent(body, "        ")
        + textwrap.dedent("""
                except Exception as e:
                    import traceback
                    result["success"] = False
                    result["error"] = {
                        "type": type(e).__name__,
                        "message": str(e),
                        "traceback": traceback.format_exc(),
                    }

                with open(RESULT_PATH, "w") as f:
                    json.dump(result, f)

            main()
            idc.qexit(0)
            """)
    )


# ---------------------------------------------------------------------------
# Operation-specific script body generators
# ---------------------------------------------------------------------------

def _body_list_functions(params: dict) -> str:
    filter_pattern = params.get("filter_pattern")
    lines = [
        'import fnmatch',
        'funcs = []',
        'for ea in idautils.Functions():',
        '    name = idc.get_func_name(ea)',
        '    func = ida_funcs.get_func(ea)',
        '    if func is None:',
        '        continue',
        '    size = func.size()',
        '    end_ea = func.start_ea + size',
    ]
    if filter_pattern:
        lines.append(f'    if not fnmatch.fnmatch(name, {filter_pattern!r}):')
        lines.append('        continue')
    lines += [
        '    funcs.append({',
        '        "ea": hex(ea),',
        '        "name": name,',
        '        "end_ea": hex(end_ea),',
        '        "size": size,',
        '    })',
        'result["success"] = True',
        'result["data"] = {"functions": funcs}',
    ]
    return "\n".join(lines) + "\n"


def _body_get_function_details(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {{hex(ea)}}")
        name = idc.get_func_name(ea)
        size = func.size()
        end_ea = func.start_ea + size
        # Count basic blocks via FlowChart
        from ida_gdl import FlowChart
        fc = FlowChart(func)
        num_blocks = sum(1 for _ in fc)
        cc = idc.get_func_attr(ea, idc.FUNCATTR_CC)
        frame_size = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
        result["success"] = True
        result["data"] = {{
            "ea": hex(ea),
            "name": name,
            "end_ea": hex(end_ea),
            "size": size,
            "num_blocks": num_blocks,
            "calling_convention": str(cc),
            "frame_size": frame_size,
        }}
    """)


def _body_rename_function(params: dict) -> str:
    ea = params["ea"]
    new_name = params["new_name"]
    return textwrap.dedent(f"""\
        ea = {ea}
        if ida_funcs.get_func(ea) is None:
            raise ValueError(f"No function at {{hex(ea)}}")
        ok = idc.set_name(ea, {new_name!r}, idc.SN_CHECK)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Renamed to {new_name}" if ok else "Rename failed"}}
    """)


def _body_create_function(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        ok = ida_funcs.add_func(ea)
        result["success"] = bool(ok)
        result["data"] = {{"message": f"Created function at {{hex(ea)}}" if ok else "Failed to create function"}}
    """)


def _body_delete_function(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {{hex(ea)}}")
        ok = ida_funcs.del_func(ea)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Function deleted" if ok else "Delete failed"}}
    """)


def _body_decompile(params: dict) -> str:
    ea = params["ea"]
    var_hints = params.get("var_hints")
    lines = [
        f'ea = {ea}',
        'func = ida_funcs.get_func(ea)',
        'if func is None:',
        '    raise ValueError(f"No function at {hex(ea)}")',
        'try:',
        '    cfunc = ida_hexrays.decompile(ea)',
        'except ida_hexrays.DecompilationFailure as e:',
        '    raise RuntimeError(f"Decompilation failed: {e}")',
        'pseudocode = str(cfunc)',
    ]
    if var_hints:
        for old_name, new_name in var_hints.items():
            lines.append(f'pseudocode = pseudocode.replace({old_name!r}, {new_name!r})')
    lines += [
        'name = idc.get_func_name(ea)',
        'tinfo = ida_typeinf.tinfo_t()',
        'param_types = []',
        'if ida_typeinf.guess_tinfo(tinfo, ea):',
        '    func_data = ida_typeinf.func_type_data_t()',
        '    if tinfo.get_func_details(func_data):',
        '        for i in range(func_data.size()):',
        '            param_types.append(str(func_data[i].type))',
        'result["success"] = True',
        'result["data"] = {',
        '    "ea": hex(ea),',
        '    "name": name,',
        '    "pseudocode": pseudocode,',
        '    "parameter_types": param_types,',
        '}',
    ]
    return "\n".join(lines) + "\n"


def _body_disassemble_at(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        size = idc.get_item_size(ea)
        raw = ida_bytes.get_bytes(ea, size)
        raw_hex = raw.hex() if raw else ""
        mnemonic = idc.print_insn_mnem(ea)
        operands = idc.print_operand(ea, 0)
        op1 = idc.print_operand(ea, 1)
        if op1:
            operands += ", " + op1
        comment = idc.get_cmt(ea, 0) or idc.get_cmt(ea, 1)
        result["success"] = True
        result["data"] = {{
            "ea": hex(ea),
            "raw_bytes": raw_hex,
            "mnemonic": mnemonic,
            "operands": operands,
            "comment": comment,
        }}
    """)


def _body_disassemble_range(params: dict) -> str:
    start_ea = params["start_ea"]
    end_ea = params["end_ea"]
    return textwrap.dedent(f"""\
        instructions = []
        ea = {start_ea}
        end = {end_ea}
        while ea < end and ea != idc.BADADDR:
            size = idc.get_item_size(ea)
            raw = ida_bytes.get_bytes(ea, size)
            raw_hex = raw.hex() if raw else ""
            mnemonic = idc.print_insn_mnem(ea)
            operands = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if op1:
                operands += ", " + op1
            comment = idc.get_cmt(ea, 0) or idc.get_cmt(ea, 1)
            instructions.append({{
                "ea": hex(ea),
                "raw_bytes": raw_hex,
                "mnemonic": mnemonic,
                "operands": operands,
                "comment": comment,
            }})
            ea = idc.next_head(ea, end)
        result["success"] = True
        result["data"] = {{"instructions": instructions}}
    """)


def _body_disassemble_function(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {{hex(ea)}}")
        instructions = []
        addr = func.start_ea
        end = func.start_ea + func.size()
        while addr < end and addr != idc.BADADDR:
            size = idc.get_item_size(addr)
            raw = ida_bytes.get_bytes(addr, size)
            raw_hex = raw.hex() if raw else ""
            mnemonic = idc.print_insn_mnem(addr)
            operands = idc.print_operand(addr, 0)
            op1 = idc.print_operand(addr, 1)
            if op1:
                operands += ", " + op1
            comment = idc.get_cmt(addr, 0) or idc.get_cmt(addr, 1)
            instructions.append({{
                "ea": hex(addr),
                "raw_bytes": raw_hex,
                "mnemonic": mnemonic,
                "operands": operands,
                "comment": comment,
            }})
            addr = idc.next_head(addr, end)
        result["success"] = True
        result["data"] = {{"instructions": instructions}}
    """)


def _body_get_xrefs_to(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        xrefs = []
        for xref in idautils.XrefsTo(ea, 0):
            xtype = "code_call"
            if xref.type in (idautils.ida_xref.fl_JN, idautils.ida_xref.fl_JF):
                xtype = "code_jump"
            elif xref.type in (idautils.ida_xref.dr_R,):
                xtype = "data_read"
            elif xref.type in (idautils.ida_xref.dr_W,):
                xtype = "data_write"
            elif xref.type in (idautils.ida_xref.dr_O,):
                xtype = "data_offset"
            src_func = idc.get_func_name(xref.frm)
            tgt_func = idc.get_func_name(ea)
            xrefs.append({{
                "source_ea": hex(xref.frm),
                "target_ea": hex(ea),
                "xref_type": xtype,
                "source_function": src_func or None,
                "target_function": tgt_func or None,
            }})
        result["success"] = True
        result["data"] = {{"xrefs": xrefs}}
    """)


def _body_get_xrefs_from(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        xrefs = []
        for xref in idautils.XrefsFrom(ea, 0):
            xtype = "code_call"
            if xref.type in (idautils.ida_xref.fl_JN, idautils.ida_xref.fl_JF):
                xtype = "code_jump"
            elif xref.type in (idautils.ida_xref.dr_R,):
                xtype = "data_read"
            elif xref.type in (idautils.ida_xref.dr_W,):
                xtype = "data_write"
            elif xref.type in (idautils.ida_xref.dr_O,):
                xtype = "data_offset"
            src_func = idc.get_func_name(ea)
            tgt_func = idc.get_func_name(xref.to)
            xrefs.append({{
                "source_ea": hex(ea),
                "target_ea": hex(xref.to),
                "xref_type": xtype,
                "source_function": src_func or None,
                "target_function": tgt_func or None,
            }})
        result["success"] = True
        result["data"] = {{"xrefs": xrefs}}
    """)


def _body_get_function_xrefs(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {{hex(ea)}}")
        callers = []
        for xref in idautils.XrefsTo(ea, 0):
            src_func = idc.get_func_name(xref.frm)
            callers.append({{
                "source_ea": hex(xref.frm),
                "target_ea": hex(ea),
                "xref_type": "code_call",
                "source_function": src_func or None,
                "target_function": idc.get_func_name(ea) or None,
            }})
        callees = []
        for head in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(head, 0):
                callee_func = ida_funcs.get_func(xref.to)
                if callee_func and callee_func.start_ea != ea:
                    name = idc.get_func_name(xref.to)
                    callees.append({{
                        "source_ea": hex(head),
                        "target_ea": hex(xref.to),
                        "xref_type": "code_call",
                        "source_function": idc.get_func_name(ea) or None,
                        "target_function": name or None,
                    }})
        result["success"] = True
        result["data"] = {{"callers": callers, "callees": callees}}
    """)


def _body_list_strings(params: dict) -> str:
    filter_pattern = params.get("filter_pattern")
    offset = params.get("offset", 0)
    limit = params.get("limit", 100)
    lines = [
        'import fnmatch',
        'all_strings = []',
        'sc = idautils.Strings()',
        'for s in sc:',
        '    val = str(s)',
        '    stype = "ascii"',
        '    if s.strtype == ida_nalt.STRTYPE_C_16:',
        '        stype = "utf16"',
        '    elif s.strtype == ida_nalt.STRTYPE_C:',
        '        stype = "ascii"',
    ]
    if filter_pattern:
        lines.append(f'    if not fnmatch.fnmatch(val, {filter_pattern!r}):')
        lines.append('        continue')
    lines += [
        '    all_strings.append({',
        '        "ea": hex(s.ea),',
        '        "value": val,',
        '        "length": s.length,',
        '        "string_type": stype,',
        '    })',
        f'total = len(all_strings)',
        f'page = all_strings[{offset}:{offset}+{limit}]',
        'result["success"] = True',
        'result["data"] = {',
        '    "strings": page,',
        '    "total_count": total,',
        f'    "offset": {offset},',
        f'    "limit": {limit},',
        '}',
    ]
    return "\n".join(lines) + "\n"


def _body_list_segments(params: dict) -> str:
    return textwrap.dedent("""\
        segments = []
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(seg_ea)
            if seg is None:
                continue
            name = idc.get_segm_name(seg_ea)
            perms = ""
            perms += "r" if seg.perm & ida_segment.SFL_READ else "-"
            perms += "w" if seg.perm & ida_segment.SFL_WRITE else "-"
            perms += "x" if seg.perm & ida_segment.SFL_EXEC else "-"
            seg_class = idc.get_segm_class(seg_ea)
            bitness_val = seg.bitness
            bitness = {0: 16, 1: 32, 2: 64}.get(bitness_val, 32)
            segments.append({
                "name": name,
                "start_ea": hex(seg.start_ea),
                "end_ea": hex(seg.end_ea),
                "size": seg.end_ea - seg.start_ea,
                "permissions": perms,
                "seg_class": seg_class or "",
                "bitness": bitness,
            })
        result["success"] = True
        result["data"] = {"segments": segments}
    """)


def _body_get_segment(params: dict) -> str:
    name_or_ea = params["name_or_ea"]
    return textwrap.dedent(f"""\
        name_or_ea = {name_or_ea!r}
        seg = ida_segment.get_segm_by_name(name_or_ea)
        if seg is None:
            try:
                addr = int(name_or_ea, 0)
                seg = ida_segment.getseg(addr)
            except (ValueError, TypeError):
                pass
        if seg is None:
            raise ValueError(f"Segment not found: {{name_or_ea}}")
        name = idc.get_segm_name(seg.start_ea)
        perms = ""
        perms += "r" if seg.perm & ida_segment.SFL_READ else "-"
        perms += "w" if seg.perm & ida_segment.SFL_WRITE else "-"
        perms += "x" if seg.perm & ida_segment.SFL_EXEC else "-"
        seg_class = idc.get_segm_class(seg.start_ea)
        bitness = {{0: 16, 1: 32, 2: 64}}.get(seg.bitness, 32)
        result["success"] = True
        result["data"] = {{
            "name": name,
            "start_ea": hex(seg.start_ea),
            "end_ea": hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "permissions": perms,
            "seg_class": seg_class or "",
            "bitness": bitness,
        }}
    """)


def _body_get_segment_at(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        seg = ida_segment.getseg(ea)
        if seg is None:
            raise ValueError(f"No segment at {{hex(ea)}}")
        name = idc.get_segm_name(seg.start_ea)
        perms = ""
        perms += "r" if seg.perm & ida_segment.SFL_READ else "-"
        perms += "w" if seg.perm & ida_segment.SFL_WRITE else "-"
        perms += "x" if seg.perm & ida_segment.SFL_EXEC else "-"
        seg_class = idc.get_segm_class(seg.start_ea)
        bitness = {{0: 16, 1: 32, 2: 64}}.get(seg.bitness, 32)
        result["success"] = True
        result["data"] = {{
            "name": name,
            "start_ea": hex(seg.start_ea),
            "end_ea": hex(seg.end_ea),
            "size": seg.end_ea - seg.start_ea,
            "permissions": perms,
            "seg_class": seg_class or "",
            "bitness": bitness,
        }}
    """)


def _body_list_imports(params: dict) -> str:
    library = params.get("library")
    lines = [
        'imports = []',
        'nimps = ida_nalt.get_import_module_qty()',
        'for i in range(nimps):',
        '    mod_name = ida_nalt.get_import_module_name(i)',
        '    if mod_name is None:',
        '        continue',
    ]
    if library:
        lines.append(f'    if mod_name != {library!r}:')
        lines.append('        continue')
    lines += [
        '    def imp_cb(ea, name, ordinal):',
        '        imports.append({',
        '            "library": mod_name,',
        '            "name": name or "",',
        '            "ordinal": ordinal,',
        '            "ea": hex(ea),',
        '        })',
        '        return True',
        '    ida_nalt.enum_import_names(i, imp_cb)',
        'result["success"] = True',
        'result["data"] = {"imports": imports}',
    ]
    return "\n".join(lines) + "\n"


def _body_list_exports(params: dict) -> str:
    return textwrap.dedent("""\
        exports = []
        for i, entry in enumerate(idautils.Entries()):
            idx, ordinal, ea, name = entry
            exports.append({
                "name": name or "",
                "ordinal": ordinal,
                "ea": hex(ea),
            })
        result["success"] = True
        result["data"] = {"exports": exports}
    """)


def _body_list_types(params: dict) -> str:
    return textwrap.dedent("""\
        types = []
        til = ida_typeinf.get_idati()
        for ordinal in range(1, ida_typeinf.get_ordinal_qty(til) + 1):
            tinfo = ida_typeinf.tinfo_t()
            if tinfo.get_numbered_type(til, ordinal):
                name = tinfo.get_type_name()
                size = tinfo.get_size()
                definition = str(tinfo)
                types.append({
                    "name": name or "",
                    "size": size if size != ida_typeinf.BADSIZE else 0,
                    "definition": definition,
                })
        result["success"] = True
        result["data"] = {"types": types}
    """)


def _body_create_struct(params: dict) -> str:
    name = params["name"]
    fields = params.get("fields", [])
    lines = [
        f'sid = ida_struct.add_struc(-1, {name!r}, 0)',
        'if sid == idc.BADADDR:',
        f'    raise ValueError("Failed to create struct \'{name}\' — name may conflict")',
        f'sptr = ida_struct.get_struc(sid)',
    ]
    for fld in fields:
        fname = fld["name"]
        ftype = fld.get("type_str", "int")
        foffset = fld.get("offset", -1)
        size_map = {"int": 4, "char": 1, "short": 2, "long": 8, "float": 4, "double": 8, "void*": 8}
        fsize = size_map.get(ftype, 4)
        lines.append(
            f'ida_struct.add_struc_member(sptr, {fname!r}, {foffset}, '
            f'idc.FF_DWORD, None, {fsize})'
        )
    lines += [
        'result["success"] = True',
        f'result["data"] = {{"message": "Created struct \'{name}\'"}}',
    ]
    return "\n".join(lines) + "\n"


def _body_add_struct_field(params: dict) -> str:
    struct_name = params["struct_name"]
    fld = params["field"]
    fname = fld["name"]
    ftype = fld.get("type_str", "int")
    foffset = fld.get("offset", -1)
    size_map = {"int": 4, "char": 1, "short": 2, "long": 8, "float": 4, "double": 8, "void*": 8}
    fsize = size_map.get(ftype, 4)
    return textwrap.dedent(f"""\
        sid = ida_struct.get_struc_id({struct_name!r})
        if sid == idc.BADADDR:
            raise ValueError(f"Struct '{struct_name}' not found")
        sptr = ida_struct.get_struc(sid)
        err = ida_struct.add_struc_member(sptr, {fname!r}, {foffset}, idc.FF_DWORD, None, {fsize})
        result["success"] = err == 0
        result["data"] = {{"message": "Added field '{fname}'" if err == 0 else f"Failed (error {{err}})"}}
    """)


def _body_apply_type(params: dict) -> str:
    ea = params["ea"]
    type_str = params["type_str"]
    return textwrap.dedent(f"""\
        ea = {ea}
        tinfo = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tinfo, None, {type_str!r} + ";", 0):
            raise ValueError(f"Failed to parse type: {type_str}")
        ok = ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Type applied" if ok else "Failed to apply type"}}
    """)


def _body_delete_type(params: dict) -> str:
    name = params["name"]
    return textwrap.dedent(f"""\
        til = ida_typeinf.get_idati()
        ordinal = ida_typeinf.get_type_ordinal(til, {name!r})
        if ordinal == 0:
            raise ValueError(f"Type '{name}' not found")
        ok = ida_typeinf.del_numbered_type(til, ordinal)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Deleted type '{name}'" if ok else "Failed to delete type"}}
    """)


def _body_parse_header(params: dict) -> str:
    header_text = params["header_text"]
    return textwrap.dedent(f"""\
        errors = ida_typeinf.idc_parse_types({header_text!r}, 0)
        result["success"] = errors == 0
        result["data"] = {{"message": "Header parsed" if errors == 0 else f"Parse errors: {{errors}}"}}
    """)


def _body_set_comment(params: dict) -> str:
    ea = params["ea"]
    comment = params["comment"]
    comment_type = params.get("comment_type", "regular")
    if comment_type == "regular":
        return textwrap.dedent(f"""\
            ea = {ea}
            idc.set_cmt(ea, {comment!r}, 0)
            result["success"] = True
            result["data"] = {{"message": "Comment set"}}
        """)
    elif comment_type == "repeatable":
        return textwrap.dedent(f"""\
            ea = {ea}
            idc.set_cmt(ea, {comment!r}, 1)
            result["success"] = True
            result["data"] = {{"message": "Repeatable comment set"}}
        """)
    else:  # function
        return textwrap.dedent(f"""\
            ea = {ea}
            func = ida_funcs.get_func(ea)
            if func is None:
                raise ValueError(f"No function at {{hex(ea)}}")
            idc.set_func_cmt(ea, {comment!r}, 0)
            result["success"] = True
            result["data"] = {{"message": "Function comment set"}}
        """)


def _body_get_comments(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        regular = idc.get_cmt(ea, 0)
        repeatable = idc.get_cmt(ea, 1)
        func_cmt = None
        func = ida_funcs.get_func(ea)
        if func:
            func_cmt = idc.get_func_cmt(ea, 0)
        result["success"] = True
        result["data"] = {{
            "ea": hex(ea),
            "regular": regular or None,
            "repeatable": repeatable or None,
            "function_comment": func_cmt or None,
        }}
    """)


def _body_get_comments_range(params: dict) -> str:
    start_ea = params["start_ea"]
    end_ea = params["end_ea"]
    return textwrap.dedent(f"""\
        comments = []
        ea = {start_ea}
        end = {end_ea}
        while ea < end and ea != idc.BADADDR:
            regular = idc.get_cmt(ea, 0)
            repeatable = idc.get_cmt(ea, 1)
            func_cmt = None
            func = ida_funcs.get_func(ea)
            if func and func.start_ea == ea:
                func_cmt = idc.get_func_cmt(ea, 0)
            if regular or repeatable or func_cmt:
                comments.append({{
                    "ea": hex(ea),
                    "regular": regular or None,
                    "repeatable": repeatable or None,
                    "function_comment": func_cmt or None,
                }})
            ea = idc.next_head(ea, end)
        result["success"] = True
        result["data"] = {{"comments": comments}}
    """)


def _body_read_bytes(params: dict) -> str:
    ea = params["ea"]
    length = params["length"]
    return textwrap.dedent(f"""\
        ea = {ea}
        length = {length}
        seg = ida_segment.getseg(ea)
        if seg is None:
            raise ValueError(f"Address {{hex(ea)}} is unmapped")
        raw = ida_bytes.get_bytes(ea, length)
        result["success"] = True
        result["data"] = {{"hex_bytes": raw.hex() if raw else ""}}
    """)


def _body_patch_bytes(params: dict) -> str:
    ea = params["ea"]
    hex_values = params["hex_values"]
    return textwrap.dedent(f"""\
        ea = {ea}
        hex_values = {hex_values!r}
        seg = ida_segment.getseg(ea)
        if seg is None:
            raise ValueError(f"Address {{hex(ea)}} is unmapped")
        byte_vals = bytes.fromhex(hex_values)
        for i, b in enumerate(byte_vals):
            ida_bytes.patch_byte(ea + i, b)
        result["success"] = True
        result["data"] = {{"message": f"Patched {{len(byte_vals)}} bytes at {{hex(ea)}}"}}
    """)


def _body_assemble_and_patch(params: dict) -> str:
    ea = params["ea"]
    assembly = params["assembly"]
    return textwrap.dedent(f"""\
        ea = {ea}
        seg = ida_segment.getseg(ea)
        if seg is None:
            raise ValueError(f"Address {{hex(ea)}} is unmapped")
        ok, code = idc.assemble(ea, {assembly!r})
        if not ok:
            raise ValueError(f"Assembly failed: {{code}}")
        for i, b in enumerate(code):
            ida_bytes.patch_byte(ea + i, b)
        result["success"] = True
        result["data"] = {{"message": f"Assembled and patched {{len(code)}} bytes"}}
    """)


def _body_list_patches(params: dict) -> str:
    return textwrap.dedent("""\
        patches = []
        def patch_visitor(ea, fpos, original, patched):
            patches.append({
                "ea": hex(ea),
                "original_byte": f"{original:02x}",
                "patched_byte": f"{patched:02x}",
            })
            return 0
        ida_bytes.visit_patched_bytes(0, idc.BADADDR, patch_visitor)
        result["success"] = True
        result["data"] = {"patches": patches}
    """)


def _body_search_bytes(params: dict) -> str:
    pattern = params["pattern"]
    start_ea = params.get("start_ea")
    end_ea = params.get("end_ea")
    max_results = params.get("max_results", 100)
    start_expr = str(start_ea) if start_ea is not None else "idc.get_inf_attr(idc.INF_MIN_EA)"
    end_expr = str(end_ea) if end_ea is not None else "idc.get_inf_attr(idc.INF_MAX_EA)"
    return textwrap.dedent(f"""\
        pattern = {pattern!r}
        start = {start_expr}
        end = {end_expr}
        max_results = {max_results}
        results_list = []
        ea = ida_search.find_binary(start, end, pattern, 16, idc.SEARCH_DOWN)
        while ea != idc.BADADDR and len(results_list) < max_results:
            results_list.append(hex(ea))
            ea = ida_search.find_binary(ea + 1, end, pattern, 16, idc.SEARCH_DOWN)
        result["success"] = True
        result["data"] = {{"results": results_list}}
    """)


def _body_search_text(params: dict) -> str:
    text = params["text"]
    start_ea = params.get("start_ea")
    end_ea = params.get("end_ea")
    max_results = params.get("max_results", 100)
    start_expr = str(start_ea) if start_ea is not None else "idc.get_inf_attr(idc.INF_MIN_EA)"
    end_expr = str(end_ea) if end_ea is not None else "idc.get_inf_attr(idc.INF_MAX_EA)"
    return textwrap.dedent(f"""\
        text = {text!r}
        start = {start_expr}
        end = {end_expr}
        max_results = {max_results}
        results_list = []
        ea = ida_search.find_text(start, 0, 0, text, idc.SEARCH_DOWN)
        while ea != idc.BADADDR and len(results_list) < max_results:
            if ea > end:
                break
            results_list.append(hex(ea))
            ea = ida_search.find_text(ea + 1, 0, 0, text, idc.SEARCH_DOWN)
        result["success"] = True
        result["data"] = {{"results": results_list}}
    """)


def _body_search_immediate(params: dict) -> str:
    value = params["value"]
    start_ea = params.get("start_ea")
    end_ea = params.get("end_ea")
    max_results = params.get("max_results", 100)
    start_expr = str(start_ea) if start_ea is not None else "idc.get_inf_attr(idc.INF_MIN_EA)"
    end_expr = str(end_ea) if end_ea is not None else "idc.get_inf_attr(idc.INF_MAX_EA)"
    return textwrap.dedent(f"""\
        value = {value}
        start = {start_expr}
        end = {end_expr}
        max_results = {max_results}
        results_list = []
        ea = ida_search.find_imm(start, idc.SEARCH_DOWN, value)
        if isinstance(ea, tuple):
            ea = ea[0]
        while ea != idc.BADADDR and len(results_list) < max_results:
            if ea > end:
                break
            results_list.append(hex(ea))
            ea = ida_search.find_imm(ea + 1, idc.SEARCH_DOWN, value)
            if isinstance(ea, tuple):
                ea = ea[0]
        result["success"] = True
        result["data"] = {{"results": results_list}}
    """)


def _body_apply_signature(params: dict) -> str:
    sig_file = params["sig_file"]
    return textwrap.dedent(f"""\
        sig_file = {sig_file!r}
        count_before = sum(1 for _ in idautils.Functions())
        idc.plan_to_apply_idasgn(sig_file)
        idaapi.auto_wait()
        count_after = sum(1 for _ in idautils.Functions())
        matched = max(0, count_after - count_before)
        result["success"] = True
        result["data"] = {{"sig_file": sig_file, "functions_matched": matched}}
    """)


def _body_list_applied_signatures(params: dict) -> str:
    return textwrap.dedent("""\
        sigs = []
        n = ida_funcs.get_idasgn_qty()
        for i in range(n):
            desc = ida_funcs.get_idasgn_desc(i)
            if desc:
                sigs.append(desc)
        result["success"] = True
        result["data"] = {"signatures": sigs}
    """)


def _body_list_available_signatures(params: dict) -> str:
    sig_dir = params.get("signatures_dir", "")
    return textwrap.dedent(f"""\
        import os
        sig_dir = {sig_dir!r}
        if not sig_dir:
            sig_dir = os.path.join(idaapi.get_ida_subdirectory("sig"), "")
        sigs = []
        if os.path.isdir(sig_dir):
            for f in os.listdir(sig_dir):
                if f.endswith(".sig"):
                    sigs.append(f)
        result["success"] = True
        result["data"] = {{"signatures": sorted(sigs)}}
    """)


def _body_add_bookmark(params: dict) -> str:
    ea = params["ea"]
    description = params["description"]
    return textwrap.dedent(f"""\
        ea = {ea}
        slot = idaapi.get_bookmark_count()
        if slot is None:
            slot = 0
        idaapi.mark_position(ea, 0, 0, 0, slot, {description!r})
        result["success"] = True
        result["data"] = {{"message": "Bookmark added"}}
    """)


def _body_list_bookmarks(params: dict) -> str:
    return textwrap.dedent("""\
        bookmarks = []
        for i in range(1024):
            ea = idaapi.get_bookmark(i)
            if ea is None or ea == idc.BADADDR:
                break
            desc = idaapi.get_bookmark_desc(i)
            bookmarks.append({
                "ea": hex(ea),
                "description": desc or "",
            })
        result["success"] = True
        result["data"] = {"bookmarks": bookmarks}
    """)


def _body_delete_bookmark(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        found = False
        for i in range(1024):
            bm_ea = idaapi.get_bookmark(i)
            if bm_ea is None or bm_ea == idc.BADADDR:
                break
            if bm_ea == ea:
                idaapi.mark_position(ea, 0, 0, 0, i, "")
                found = True
                break
        result["success"] = found
        result["data"] = {{"message": "Bookmark deleted" if found else "Bookmark not found"}}
    """)


def _body_execute_script(params: dict) -> str:
    script = params["script"]
    return textwrap.dedent(f"""\
        import sys
        import io
        _old_stdout = sys.stdout
        _old_stderr = sys.stderr
        sys.stdout = _capture_out = io.StringIO()
        sys.stderr = _capture_err = io.StringIO()
        _return_value = None
        try:
            exec({script!r})
        except Exception as _e:
            import traceback
            result["success"] = False
            result["data"] = {{
                "exception": {{
                    "type": type(_e).__name__,
                    "message": str(_e),
                    "traceback": traceback.format_exc(),
                }}
            }}
            result["stdout"] = _capture_out.getvalue()
            result["stderr"] = _capture_err.getvalue()
            sys.stdout = _old_stdout
            sys.stderr = _old_stderr
            with open(RESULT_PATH, "w") as f:
                json.dump(result, f)
            main = lambda: None  # prevent re-entry
            return
        sys.stdout = _old_stdout
        sys.stderr = _old_stderr
        result["success"] = True
        result["data"] = None
        result["stdout"] = _capture_out.getvalue()
        result["stderr"] = _capture_err.getvalue()
        result["return_value"] = _return_value
    """)


def _body_execute_script_file(params: dict) -> str:
    script_path = params["script_path"]
    return textwrap.dedent(f"""\
        import sys
        import io
        script_path = {script_path!r}
        with open(script_path) as _f:
            _script_code = _f.read()
        _old_stdout = sys.stdout
        _old_stderr = sys.stderr
        sys.stdout = _capture_out = io.StringIO()
        sys.stderr = _capture_err = io.StringIO()
        try:
            exec(_script_code)
        except Exception as _e:
            import traceback
            result["success"] = False
            result["data"] = {{
                "exception": {{
                    "type": type(_e).__name__,
                    "message": str(_e),
                    "traceback": traceback.format_exc(),
                }}
            }}
            result["stdout"] = _capture_out.getvalue()
            result["stderr"] = _capture_err.getvalue()
            sys.stdout = _old_stdout
            sys.stderr = _old_stderr
            with open(RESULT_PATH, "w") as f:
                json.dump(result, f)
            main = lambda: None
            return
        sys.stdout = _old_stdout
        sys.stderr = _old_stderr
        result["success"] = True
        result["data"] = None
        result["stdout"] = _capture_out.getvalue()
        result["stderr"] = _capture_err.getvalue()
    """)


def _body_list_enums(params: dict) -> str:
    return textwrap.dedent("""\
        enums = []
        for i in range(ida_enum.get_enum_qty()):
            eid = ida_enum.getn_enum(i)
            name = ida_enum.get_enum_name(eid)
            width = ida_enum.get_enum_width(eid)
            count = ida_enum.get_enum_size(eid)
            enums.append({
                "name": name or "",
                "member_count": count,
                "width": width,
            })
        result["success"] = True
        result["data"] = {"enums": enums}
    """)


def _body_create_enum(params: dict) -> str:
    name = params["name"]
    members = params.get("members", [])
    lines = [
        f'eid = ida_enum.add_enum(idc.BADADDR, {name!r}, 0)',
        'if eid == idc.BADADDR:',
        f'    raise ValueError("Failed to create enum \'{name}\'")',
    ]
    for m in members:
        mname = m["name"]
        mval = m["value"]
        lines.append(f'ida_enum.add_enum_member(eid, {mname!r}, {mval})')
    lines += [
        'result["success"] = True',
        f'result["data"] = {{"message": "Created enum \'{name}\'"}}',
    ]
    return "\n".join(lines) + "\n"


def _body_add_enum_member(params: dict) -> str:
    enum_name = params["enum_name"]
    member_name = params["member_name"]
    value = params["value"]
    return textwrap.dedent(f"""\
        eid = ida_enum.get_enum({enum_name!r})
        if eid == idc.BADADDR:
            raise ValueError(f"Enum '{enum_name}' not found")
        err = ida_enum.add_enum_member(eid, {member_name!r}, {value})
        result["success"] = err == 0
        result["data"] = {{"message": "Added member '{member_name}'" if err == 0 else f"Failed (error {{err}})"}}
    """)


def _body_apply_enum(params: dict) -> str:
    ea = params["ea"]
    operand = params["operand"]
    enum_name = params["enum_name"]
    return textwrap.dedent(f"""\
        ea = {ea}
        eid = ida_enum.get_enum({enum_name!r})
        if eid == idc.BADADDR:
            raise ValueError(f"Enum '{enum_name}' not found")
        ok = idc.op_enum(ea, {operand}, eid, 0)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Enum applied" if ok else "Failed to apply enum"}}
    """)


def _body_list_names(params: dict) -> str:
    return textwrap.dedent("""\
        names = []
        for ea, name in idautils.Names():
            flags = idc.get_full_flags(ea)
            ntype = None
            if idc.is_code(flags):
                ntype = "func" if ida_funcs.get_func(ea) else "code"
            elif idc.is_data(flags):
                ntype = "data"
            names.append({
                "ea": hex(ea),
                "name": name,
                "type": ntype,
            })
        result["success"] = True
        result["data"] = {"names": names}
    """)


def _body_rename_location(params: dict) -> str:
    ea = params["ea"]
    new_name = params["new_name"]
    return textwrap.dedent(f"""\
        ea = {ea}
        ok = idc.set_name(ea, {new_name!r}, idc.SN_CHECK)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Renamed to '{new_name}'" if ok else "Rename failed"}}
    """)


def _body_get_data_type(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        flags = idc.get_full_flags(ea)
        size = idc.get_item_size(ea)
        tinfo = ida_typeinf.tinfo_t()
        type_name = "byte"
        if ida_typeinf.guess_tinfo(tinfo, ea):
            type_name = str(tinfo)
        elif idc.is_dword(flags):
            type_name = "dword"
        elif idc.is_word(flags):
            type_name = "word"
        elif idc.is_qword(flags):
            type_name = "qword"
        elif idc.is_strlit(flags):
            type_name = "string"
        result["success"] = True
        result["data"] = {{"ea": hex(ea), "type_name": type_name, "size": size}}
    """)


def _body_set_data_type(params: dict) -> str:
    ea = params["ea"]
    type_str = params["type_str"]
    return textwrap.dedent(f"""\
        ea = {ea}
        tinfo = ida_typeinf.tinfo_t()
        if not ida_typeinf.parse_decl(tinfo, None, {type_str!r} + " x;", 0):
            raise ValueError(f"Failed to parse type: {type_str}")
        ok = ida_typeinf.apply_tinfo(ea, tinfo, ida_typeinf.TINFO_DEFINITE)
        result["success"] = bool(ok)
        result["data"] = {{"message": "Type set" if ok else "Failed to set type"}}
    """)


def _body_get_callers(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        callers = []
        for xref in idautils.XrefsTo(ea, 0):
            func = ida_funcs.get_func(xref.frm)
            if func:
                callers.append({{
                    "ea": hex(func.start_ea),
                    "name": idc.get_func_name(func.start_ea) or f"sub_{{func.start_ea:x}}",
                }})
        result["success"] = True
        result["data"] = {{"callers": callers}}
    """)


def _body_get_callees(params: dict) -> str:
    ea = params["ea"]
    return textwrap.dedent(f"""\
        ea = {ea}
        func = ida_funcs.get_func(ea)
        if func is None:
            raise ValueError(f"No function at {{hex(ea)}}")
        callees = []
        seen = set()
        for head in idautils.FuncItems(ea):
            for xref in idautils.XrefsFrom(head, 0):
                callee = ida_funcs.get_func(xref.to)
                if callee and callee.start_ea != ea and callee.start_ea not in seen:
                    seen.add(callee.start_ea)
                    callees.append({{
                        "ea": hex(callee.start_ea),
                        "name": idc.get_func_name(callee.start_ea) or f"sub_{{callee.start_ea:x}}",
                    }})
        result["success"] = True
        result["data"] = {{"callees": callees}}
    """)


def _body_get_call_graph(params: dict) -> str:
    ea = params["ea"]
    depth = params.get("depth", 3)
    return textwrap.dedent(f"""\
        def _build_graph(ea, depth, visited):
            name = idc.get_func_name(ea) or f"sub_{{ea:x}}"
            node = {{"ea": hex(ea), "name": name, "children": []}}
            if depth <= 0 or ea in visited:
                return node
            visited.add(ea)
            func = ida_funcs.get_func(ea)
            if func:
                seen = set()
                for head in idautils.FuncItems(ea):
                    for xref in idautils.XrefsFrom(head, 0):
                        callee = ida_funcs.get_func(xref.to)
                        if callee and callee.start_ea != ea and callee.start_ea not in seen:
                            seen.add(callee.start_ea)
                            node["children"].append(_build_graph(callee.start_ea, depth - 1, visited))
            visited.discard(ea)
            return node
        ea = {ea}
        graph = _build_graph(ea, {depth}, set())
        result["success"] = True
        result["data"] = {{"call_graph": graph}}
    """)


# ---------------------------------------------------------------------------
# Operation dispatch table
# ---------------------------------------------------------------------------

_OPERATION_BUILDERS: dict[str, Any] = {
    # Functions
    "list_functions": _body_list_functions,
    "get_function_details": _body_get_function_details,
    "rename_function": _body_rename_function,
    "create_function": _body_create_function,
    "delete_function": _body_delete_function,
    # Decompilation
    "decompile": _body_decompile,
    # Disassembly
    "disassemble_at": _body_disassemble_at,
    "disassemble_range": _body_disassemble_range,
    "disassemble_function": _body_disassemble_function,
    # Cross-references
    "get_xrefs_to": _body_get_xrefs_to,
    "get_xrefs_from": _body_get_xrefs_from,
    "get_function_xrefs": _body_get_function_xrefs,
    # Strings
    "list_strings": _body_list_strings,
    # Segments
    "list_segments": _body_list_segments,
    "get_segment": _body_get_segment,
    "get_segment_at": _body_get_segment_at,
    # Imports / Exports
    "list_imports": _body_list_imports,
    "list_exports": _body_list_exports,
    # Types
    "list_types": _body_list_types,
    "create_struct": _body_create_struct,
    "add_struct_field": _body_add_struct_field,
    "apply_type": _body_apply_type,
    "delete_type": _body_delete_type,
    "parse_header": _body_parse_header,
    # Comments
    "set_comment": _body_set_comment,
    "get_comments": _body_get_comments,
    "get_comments_range": _body_get_comments_range,
    # Patching
    "read_bytes": _body_read_bytes,
    "patch_bytes": _body_patch_bytes,
    "assemble_and_patch": _body_assemble_and_patch,
    "list_patches": _body_list_patches,
    # Search
    "search_bytes": _body_search_bytes,
    "search_text": _body_search_text,
    "search_immediate": _body_search_immediate,
    # Signatures
    "apply_signature": _body_apply_signature,
    "list_applied_signatures": _body_list_applied_signatures,
    "list_available_signatures": _body_list_available_signatures,
    # Bookmarks
    "add_bookmark": _body_add_bookmark,
    "list_bookmarks": _body_list_bookmarks,
    "delete_bookmark": _body_delete_bookmark,
    # Scripting
    "execute_script": _body_execute_script,
    "execute_script_file": _body_execute_script_file,
    # Enums
    "list_enums": _body_list_enums,
    "create_enum": _body_create_enum,
    "add_enum_member": _body_add_enum_member,
    "apply_enum": _body_apply_enum,
    # Data / Names
    "list_names": _body_list_names,
    "rename_location": _body_rename_location,
    "get_data_type": _body_get_data_type,
    "set_data_type": _body_set_data_type,
    # Call graph
    "get_callers": _body_get_callers,
    "get_callees": _body_get_callees,
    "get_call_graph": _body_get_call_graph,
}


# ---------------------------------------------------------------------------
# IdaBridge
# ---------------------------------------------------------------------------

class IdaBridge:
    """Generates IDAPython scripts and parses their JSON results.

    This is the translation layer between high-level MCP tool operations
    and IDA Pro's Python API.  Each operation is mapped to a script body
    generator that produces the operation-specific logic.  The body is
    then wrapped in the standard template (imports, try/except, JSON
    result writing, ``idc.qexit(0)``).
    """

    def build_script(self, operation: str, params: dict, result_path: str = "") -> str:
        """Generate an IDAPython script string for *operation*.

        Args:
            operation: The operation name (e.g. ``"list_functions"``).
            params: Operation-specific parameters.
            result_path: File path where the script should write its JSON
                result.  Defaults to ``"result.json"`` in the current
                directory if not specified.

        Returns:
            A complete IDAPython script as a string.

        Raises:
            ValueError: If *operation* is not a recognised operation name.
        """
        builder = _OPERATION_BUILDERS.get(operation)
        if builder is None:
            raise ValueError(f"Unknown operation: {operation}")

        if not result_path:
            result_path = "result.json"

        body = builder(params)
        return _wrap_script(body, result_path)

    def parse_result(self, result_path: Path) -> ScriptResult:
        """Parse the JSON result file written by an IDAPython script.

        Args:
            result_path: Path to the JSON result file.

        Returns:
            A :class:`ScriptResult` populated from the file contents.

        Raises:
            FileNotFoundError: If *result_path* does not exist.
            json.JSONDecodeError: If the file contains invalid JSON.
        """
        with open(result_path) as f:
            data = json.load(f)

        return ScriptResult(
            success=data.get("success", False),
            data=data.get("data"),
            stdout=data.get("stdout", ""),
            stderr=data.get("stderr", ""),
            return_value=data.get("return_value"),
        )
