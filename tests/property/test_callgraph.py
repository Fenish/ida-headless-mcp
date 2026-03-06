"""Property-based tests for call graph depth invariant.

Property 28 from the IDA Headless MCP design document.
"""

from __future__ import annotations

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from ida_headless_mcp.models import CallGraphNode, FunctionRef
from tests.conftest import MockIdaBridge
from tests.strategies import function_names


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _max_depth(node: CallGraphNode) -> int:
    """Return the maximum number of edges from *node* to any leaf."""
    if not node.children:
        return 0
    return 1 + max(_max_depth(c) for c in node.children)


def _all_nodes(node: CallGraphNode) -> list[CallGraphNode]:
    """Collect every node in the tree (BFS)."""
    result: list[CallGraphNode] = []
    stack = [node]
    while stack:
        n = stack.pop()
        result.append(n)
        stack.extend(n.children)
    return result


# ===================================================================
# Property 28: Call graph depth invariant
# ===================================================================


class TestCallGraphDepthInvariant:
    """Property 28: Call graph depth invariant.

    *For any* call graph rooted at a function with depth D, no path from
    the root node to any leaf node should have more than D edges. Each
    node must contain ea and name fields.

    **Validates: Requirements 21.1, 21.2, 21.3**
    """

    # ---------------------------------------------------------------
    # 28a: Chain of functions — depth never exceeds D
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        chain_len=st.integers(min_value=2, max_value=8),
        depth=st.integers(min_value=1, max_value=8),
        data=st.data(),
    )
    def test_call_graph_depth_bounded(
        self, chain_len: int, depth: int, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 21.1, 21.3**"""
        bridge = MockIdaBridge()

        # Build a linear chain: f0 -> f1 -> f2 -> ... -> f(chain_len-1)
        eas = list(range(0x1000, 0x1000 + chain_len * 0x100, 0x100))
        names = [data.draw(function_names) for _ in eas]

        for ea, name in zip(eas, names):
            bridge.add_function(ea, name, 0x10)

        for i in range(len(eas) - 1):
            bridge.add_xref(eas[i], eas[i + 1])

        root = bridge.get_call_graph(eas[0], depth=depth)
        assert _max_depth(root) <= depth

    # ---------------------------------------------------------------
    # 28b: All nodes have non-empty ea and name
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        chain_len=st.integers(min_value=2, max_value=6),
        depth=st.integers(min_value=1, max_value=6),
        data=st.data(),
    )
    def test_all_nodes_have_ea_and_name(
        self, chain_len: int, depth: int, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 21.1, 21.2, 21.3**"""
        bridge = MockIdaBridge()

        eas = list(range(0x1000, 0x1000 + chain_len * 0x100, 0x100))
        names = [data.draw(function_names) for _ in eas]

        for ea, name in zip(eas, names):
            bridge.add_function(ea, name, 0x10)

        for i in range(len(eas) - 1):
            bridge.add_xref(eas[i], eas[i + 1])

        root = bridge.get_call_graph(eas[0], depth=depth)
        for node in _all_nodes(root):
            assert node.ea, "node.ea must be non-empty"
            assert node.name, "node.name must be non-empty"

    # ---------------------------------------------------------------
    # 28c: get_callers returns correct callers after add_xref
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        num_callers=st.integers(min_value=1, max_value=6),
        data=st.data(),
    )
    def test_get_callers_correct(
        self, num_callers: int, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 21.1**"""
        bridge = MockIdaBridge()

        target_ea = 0x5000
        target_name = data.draw(function_names)
        bridge.add_function(target_ea, target_name, 0x10)

        caller_eas: list[int] = []
        for i in range(num_callers):
            ea = 0x1000 + i * 0x100
            name = data.draw(function_names)
            bridge.add_function(ea, name, 0x10)
            bridge.add_xref(ea, target_ea)
            caller_eas.append(ea)

        callers = bridge.get_callers(target_ea)
        caller_ea_strs = {c.ea for c in callers}

        for ea in caller_eas:
            assert f"0x{ea:x}" in caller_ea_strs

        assert len(callers) == num_callers

    # ---------------------------------------------------------------
    # 28d: get_callees returns correct callees after add_xref
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        num_callees=st.integers(min_value=1, max_value=6),
        data=st.data(),
    )
    def test_get_callees_correct(
        self, num_callees: int, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 21.2**"""
        bridge = MockIdaBridge()

        source_ea = 0x5000
        source_name = data.draw(function_names)
        bridge.add_function(source_ea, source_name, 0x10)

        callee_eas: list[int] = []
        for i in range(num_callees):
            ea = 0x1000 + i * 0x100
            name = data.draw(function_names)
            bridge.add_function(ea, name, 0x10)
            bridge.add_xref(source_ea, ea)
            callee_eas.append(ea)

        callees = bridge.get_callees(source_ea)
        callee_ea_strs = {c.ea for c in callees}

        for ea in callee_eas:
            assert f"0x{ea:x}" in callee_ea_strs

        assert len(callees) == num_callees

    # ---------------------------------------------------------------
    # 28e: Cycle detection — A->B->A terminates without infinite loop
    # ---------------------------------------------------------------

    @settings(max_examples=100)
    @given(
        depth=st.integers(min_value=1, max_value=10),
        data=st.data(),
    )
    def test_cycle_detection_terminates(
        self, depth: int, data: st.DataObject
    ) -> None:
        """**Validates: Requirements 21.3**"""
        bridge = MockIdaBridge()

        ea_a = 0x1000
        ea_b = 0x2000
        name_a = data.draw(function_names)
        name_b = data.draw(function_names)

        bridge.add_function(ea_a, name_a, 0x10)
        bridge.add_function(ea_b, name_b, 0x10)

        # Create cycle: A -> B -> A
        bridge.add_xref(ea_a, ea_b)
        bridge.add_xref(ea_b, ea_a)

        root = bridge.get_call_graph(ea_a, depth=depth)

        # Must terminate and produce a valid tree
        assert root.ea == f"0x{ea_a:x}"
        assert root.name == name_a
        # Depth must still be bounded
        assert _max_depth(root) <= depth
