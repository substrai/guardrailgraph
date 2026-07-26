"""Check dependency graph visualization with DOT/Mermaid export.

Generates visual DAG representations of guardrail pipelines for
documentation and debugging. Exports to Graphviz DOT format and
Mermaid diagram syntax.

Usage:
    from guardrailgraph.pipeline.graph_viz import PipelineGraphVisualizer

    viz = PipelineGraphVisualizer(pipeline)
    dot = viz.to_dot()
    mermaid = viz.to_mermaid()

    viz.save("pipeline_graph.dot")
    viz.save("pipeline_graph.md", format="mermaid")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class NodeType(str, Enum):
    """Type of node in the pipeline graph."""

    INPUT = "input"
    CHECK = "check"
    OUTPUT = "output"
    GATE = "gate"  # Decision node (pass/block)


class EdgeType(str, Enum):
    """Type of edge connecting nodes."""

    SEQUENTIAL = "sequential"  # A runs then B
    PARALLEL = "parallel"  # A and B run concurrently
    CONDITIONAL = "conditional"  # Runs only if condition met
    DEPENDENCY = "dependency"  # B requires A's output


@dataclass
class GraphNode:
    """A node in the pipeline graph."""

    id: str
    label: str
    node_type: NodeType
    action: str = "allow"
    threshold: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """An edge connecting two nodes."""

    source: str
    target: str
    edge_type: EdgeType
    label: str = ""


@dataclass
class PipelineGraph:
    """Graph representation of a guardrail pipeline."""

    name: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    mode: str = "fail-closed"

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Get a node by ID."""
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_dependencies(self, node_id: str) -> List[str]:
        """Get IDs of nodes that must run before this node."""
        return [
            e.source for e in self.edges
            if e.target == node_id and e.edge_type == EdgeType.DEPENDENCY
        ]

    def get_parallel_nodes(self) -> List[List[str]]:
        """Get groups of nodes that can run in parallel."""
        parallel_groups: List[List[str]] = []
        visited: Set[str] = set()

        for edge in self.edges:
            if edge.edge_type == EdgeType.PARALLEL and edge.source not in visited:
                group = [edge.source]
                visited.add(edge.source)
                for other_edge in self.edges:
                    if (other_edge.edge_type == EdgeType.PARALLEL
                            and other_edge.target == edge.target
                            and other_edge.source not in visited):
                        group.append(other_edge.source)
                        visited.add(other_edge.source)
                if len(group) > 1:
                    parallel_groups.append(group)

        return parallel_groups


class PipelineGraphVisualizer:
    """Generates visual representations of guardrail pipelines.

    Builds a graph from pipeline configuration and exports to
    Graphviz DOT or Mermaid format.

    Args:
        pipeline_config: Pipeline configuration dictionary.
            Can include 'name', 'checks', 'mode', 'parallel'.
    """

    def __init__(self, pipeline_config: Optional[Dict[str, Any]] = None):
        self._config = pipeline_config or {}
        self._graph = self._build_graph()

    @property
    def graph(self) -> PipelineGraph:
        """The built pipeline graph."""
        return self._graph

    def to_dot(self, include_metadata: bool = False) -> str:
        """Export the graph to Graphviz DOT format.

        Args:
            include_metadata: Whether to include threshold/action metadata.

        Returns:
            DOT language string for the pipeline graph.
        """
        lines: List[str] = []
        graph = self._graph

        lines.append(f'digraph "{graph.name}" {{')
        lines.append('  rankdir=TB;')
        lines.append('  node [fontname="Helvetica", fontsize=11];')
        lines.append('  edge [fontsize=9];')
        lines.append('  bgcolor="white";')
        lines.append('')

        # Node styles by type
        styles = {
            NodeType.INPUT: 'shape=rectangle, style=filled, fillcolor="#E3F2FD", color="#1565C0"',
            NodeType.CHECK: 'shape=rectangle, style=filled, fillcolor="#F3E5F5", color="#6A1B9A"',
            NodeType.OUTPUT: 'shape=rectangle, style=filled, fillcolor="#E8F5E9", color="#2E7D32"',
            NodeType.GATE: 'shape=diamond, style=filled, fillcolor="#FFF8E1", color="#F57F17"',
        }

        # Action colors
        action_colors = {
            "block": "#FFCDD2",
            "redact": "#FFF9C4",
            "flag_for_review": "#E3F2FD",
            "log": "#F1F8E9",
            "allow": "#E8F5E9",
        }

        # Emit nodes
        for node in graph.nodes:
            style = styles.get(node.node_type, 'shape=rectangle')
            if node.node_type == NodeType.CHECK:
                fill_color = action_colors.get(node.action, "#F3E5F5")
                style = f'shape=rectangle, style=filled, fillcolor="{fill_color}", color="#6A1B9A"'

            label = node.label
            if include_metadata and node.node_type == NodeType.CHECK:
                label = f"{node.label}\\n[{node.action} @ {node.threshold}]"

            lines.append(f'  "{node.id}" [{style}, label="{label}"];')

        lines.append('')

        # Emit edges
        edge_styles = {
            EdgeType.SEQUENTIAL: 'style=solid, color="#333333"',
            EdgeType.PARALLEL: 'style=dashed, color="#666666"',
            EdgeType.CONDITIONAL: 'style=dotted, color="#999999"',
            EdgeType.DEPENDENCY: 'style=solid, color="#CC0000", arrowhead=open',
        }

        for edge in graph.edges:
            style = edge_styles.get(edge.edge_type, 'style=solid')
            label_attr = f', label="{edge.label}"' if edge.label else ''
            lines.append(f'  "{edge.source}" -> "{edge.target}" [{style}{label_attr}];')

        # Add legend
        lines.append('')
        lines.append('  subgraph cluster_legend {')
        lines.append('    label="Legend"; style=filled; fillcolor="#FAFAFA"; color="#CCCCCC";')
        lines.append('    fontsize=9;')
        lines.append('    l1 [label="block", shape=rectangle, style=filled, fillcolor="#FFCDD2", color="#6A1B9A", fontsize=9];')
        lines.append('    l2 [label="redact", shape=rectangle, style=filled, fillcolor="#FFF9C4", color="#6A1B9A", fontsize=9];')
        lines.append('    l3 [label="flag", shape=rectangle, style=filled, fillcolor="#E3F2FD", color="#6A1B9A", fontsize=9];')
        lines.append('    l1 -> l2 [style=invis]; l2 -> l3 [style=invis];')
        lines.append('  }')

        lines.append('}')
        return '\n'.join(lines)

    def to_mermaid(self) -> str:
        """Export the graph to Mermaid diagram syntax.

        Returns:
            Mermaid flowchart definition string.
        """
        lines: List[str] = []
        graph = self._graph

        lines.append(f'---')
        lines.append(f'title: {graph.name} — Guardrail Pipeline')
        lines.append(f'---')
        lines.append('flowchart TD')
        lines.append('')

        # Node shapes
        shape_map = {
            NodeType.INPUT: ('[', ']'),
            NodeType.CHECK: ('(', ')'),
            NodeType.OUTPUT: ('([', '])'),
            NodeType.GATE: ('{', '}'),
        }

        # Style classes
        lines.append('    classDef input fill:#E3F2FD,stroke:#1565C0,color:#000')
        lines.append('    classDef check fill:#F3E5F5,stroke:#6A1B9A,color:#000')
        lines.append('    classDef output fill:#E8F5E9,stroke:#2E7D32,color:#000')
        lines.append('    classDef gate fill:#FFF8E1,stroke:#F57F17,color:#000')
        lines.append('    classDef block fill:#FFCDD2,stroke:#6A1B9A,color:#000')
        lines.append('    classDef redact fill:#FFF9C4,stroke:#6A1B9A,color:#000')
        lines.append('')

        # Emit nodes
        for node in graph.nodes:
            open_br, close_br = shape_map.get(node.node_type, ('[', ']'))
            safe_id = node.id.replace('-', '_').replace('.', '_')
            label = node.label

            if node.node_type == NodeType.CHECK:
                label = f"{node.label}<br/><small>{node.action}</small>"

            lines.append(f'    {safe_id}{open_br}"{label}"{close_br}')

        lines.append('')

        # Emit edges
        edge_style_map = {
            EdgeType.SEQUENTIAL: '-->',
            EdgeType.PARALLEL: '-.->', 
            EdgeType.CONDITIONAL: '-.->',
            EdgeType.DEPENDENCY: '===>',
        }

        for edge in graph.edges:
            arrow = edge_style_map.get(edge.edge_type, '-->')
            src = edge.source.replace('-', '_').replace('.', '_')
            tgt = edge.target.replace('-', '_').replace('.', '_')
            if edge.label:
                lines.append(f'    {src} {arrow}|"{edge.label}"| {tgt}')
            else:
                lines.append(f'    {src} {arrow} {tgt}')

        lines.append('')

        # Apply classes
        for node in graph.nodes:
            safe_id = node.id.replace('-', '_').replace('.', '_')
            if node.node_type == NodeType.CHECK:
                cls = node.action if node.action in ("block", "redact") else "check"
            else:
                cls = node.node_type.value
            lines.append(f'    class {safe_id} {cls}')

        return '\n'.join(lines)

    def save(self, path: str, format: str = "dot", include_metadata: bool = False) -> str:
        """Save the graph to a file.

        Args:
            path: Output file path.
            format: 'dot' or 'mermaid'.
            include_metadata: Include threshold/action in node labels.

        Returns:
            Absolute path of the saved file.
        """
        if format == "mermaid":
            content = self.to_mermaid()
        else:
            content = self.to_dot(include_metadata=include_metadata)

        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content)
        return str(file_path.resolve())

    def get_execution_order(self) -> List[List[str]]:
        """Get nodes grouped by execution order (topological sort layers).

        Returns:
            List of layers, where each layer contains node IDs
            that can execute concurrently.
        """
        graph = self._graph
        in_degree: Dict[str, int] = {node.id: 0 for node in graph.nodes}

        for edge in graph.edges:
            if edge.edge_type in (EdgeType.SEQUENTIAL, EdgeType.DEPENDENCY):
                if edge.target in in_degree:
                    in_degree[edge.target] += 1

        layers: List[List[str]] = []
        remaining = set(in_degree.keys())

        while remaining:
            # Find all nodes with no dependencies in remaining set
            layer = [
                node_id for node_id in remaining
                if in_degree[node_id] == 0
            ]
            if not layer:
                # Cycle or all remaining have dependencies — add them all
                layers.append(list(remaining))
                break

            layers.append(sorted(layer))
            for node_id in layer:
                remaining.remove(node_id)
                # Reduce in-degree for successors
                for edge in graph.edges:
                    if edge.source == node_id and edge.target in in_degree:
                        in_degree[edge.target] = max(0, in_degree[edge.target] - 1)

        return layers

    def _build_graph(self) -> PipelineGraph:
        """Build graph from pipeline configuration."""
        name = self._config.get("name", "guardrail-pipeline")
        mode = self._config.get("mode", "fail-closed")
        checks = self._config.get("checks", [])
        parallel = self._config.get("parallel", False)

        nodes: List[GraphNode] = []
        edges: List[GraphEdge] = []

        # Add input node
        nodes.append(GraphNode(
            id="input",
            label="Input Text",
            node_type=NodeType.INPUT,
        ))

        prev_id = "input"

        for check in checks:
            check_id = check.get("id", check.get("name", f"check_{len(nodes)}"))
            check_name = check.get("name", check_id)
            action = check.get("action", "block")
            threshold = check.get("threshold", check.get("config", {}).get("threshold", 0.5))

            nodes.append(GraphNode(
                id=check_id,
                label=check_name,
                node_type=NodeType.CHECK,
                action=action,
                threshold=threshold,
            ))

            edge_type = EdgeType.PARALLEL if parallel else EdgeType.SEQUENTIAL
            edges.append(GraphEdge(
                source=prev_id if not parallel else "input",
                target=check_id,
                edge_type=edge_type,
            ))

            if not parallel:
                prev_id = check_id

        # Add gate node
        gate_id = "decision"
        nodes.append(GraphNode(
            id=gate_id,
            label="Policy Decision",
            node_type=NodeType.GATE,
        ))

        if parallel:
            # All checks feed into gate
            for node in nodes:
                if node.node_type == NodeType.CHECK:
                    edges.append(GraphEdge(
                        source=node.id,
                        target=gate_id,
                        edge_type=EdgeType.SEQUENTIAL,
                    ))
        else:
            edges.append(GraphEdge(
                source=prev_id,
                target=gate_id,
                edge_type=EdgeType.SEQUENTIAL,
            ))

        # Add output nodes
        nodes.append(GraphNode(id="allow", label="✅ Allow", node_type=NodeType.OUTPUT))
        nodes.append(GraphNode(id="block", label="🚫 Block", node_type=NodeType.OUTPUT))

        edges.append(GraphEdge(source=gate_id, target="allow", edge_type=EdgeType.CONDITIONAL, label="pass"))
        edges.append(GraphEdge(source=gate_id, target="block", edge_type=EdgeType.CONDITIONAL, label="fail"))

        return PipelineGraph(name=name, nodes=nodes, edges=edges, mode=mode)
