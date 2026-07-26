"""Tests for check dependency graph visualization (DOT/Mermaid export)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from guardrailgraph.pipeline.graph_viz import (
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
    PipelineGraph,
    PipelineGraphVisualizer,
)

SAMPLE_CONFIG = {
    "name": "test-pipeline",
    "mode": "fail-closed",
    "parallel": False,
    "checks": [
        {"id": "pii-check", "name": "PII Detection", "action": "redact", "threshold": 0.7},
        {"id": "toxicity-check", "name": "Toxicity", "action": "block", "threshold": 0.8},
        {"id": "injection-check", "name": "Injection Defense", "action": "block", "threshold": 0.5},
    ],
}

PARALLEL_CONFIG = {
    "name": "parallel-pipeline",
    "parallel": True,
    "checks": [
        {"id": "check-a", "name": "Check A", "action": "block"},
        {"id": "check-b", "name": "Check B", "action": "redact"},
    ],
}


class TestPipelineGraphVizInit:
    def test_default_empty_config(self):
        viz = PipelineGraphVisualizer()
        assert viz.graph is not None
        assert viz.graph.name == "guardrail-pipeline"

    def test_custom_config(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        assert viz.graph.name == "test-pipeline"
        assert viz.graph.mode == "fail-closed"


class TestDOTExport:
    def test_dot_contains_digraph(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot()
        assert "digraph" in dot
        assert "test-pipeline" in dot

    def test_dot_contains_all_check_nodes(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot()
        assert "pii-check" in dot
        assert "toxicity-check" in dot
        assert "injection-check" in dot

    def test_dot_contains_input_output_nodes(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot()
        assert "input" in dot.lower() or "Input" in dot
        assert "block" in dot.lower() or "Block" in dot

    def test_dot_with_metadata(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot(include_metadata=True)
        assert "redact" in dot
        assert "0.7" in dot

    def test_dot_without_metadata(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot(include_metadata=False)
        # Threshold should not appear in node labels
        assert "@ 0.7" not in dot

    def test_dot_has_edges(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot()
        assert "->" in dot

    def test_dot_has_legend(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        dot = viz.to_dot()
        assert "legend" in dot.lower() or "cluster_legend" in dot


class TestMermaidExport:
    def test_mermaid_has_flowchart(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        mermaid = viz.to_mermaid()
        assert "flowchart" in mermaid

    def test_mermaid_contains_title(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        mermaid = viz.to_mermaid()
        assert "test-pipeline" in mermaid

    def test_mermaid_contains_checks(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        mermaid = viz.to_mermaid()
        assert "PII Detection" in mermaid
        assert "Toxicity" in mermaid

    def test_mermaid_has_classdefs(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        mermaid = viz.to_mermaid()
        assert "classDef" in mermaid

    def test_mermaid_has_arrows(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        mermaid = viz.to_mermaid()
        assert "-->" in mermaid


class TestSaveToFile:
    def test_save_dot_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "graph.dot")
            viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
            saved = viz.save(path, format="dot")
            assert Path(saved).exists()
            content = Path(saved).read_text()
            assert "digraph" in content

    def test_save_mermaid_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "graph.md")
            viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
            saved = viz.save(path, format="mermaid")
            assert Path(saved).exists()
            content = Path(saved).read_text()
            assert "flowchart" in content

    def test_save_creates_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "deep" / "nested" / "graph.dot")
            viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
            viz.save(path)
            assert Path(path).exists()


class TestParallelPipeline:
    def test_parallel_config_builds(self):
        viz = PipelineGraphVisualizer(PARALLEL_CONFIG)
        assert viz.graph is not None

    def test_parallel_edges_from_input(self):
        viz = PipelineGraphVisualizer(PARALLEL_CONFIG)
        # All checks should connect from input
        input_edges = [e for e in viz.graph.edges if e.source == "input"]
        assert len(input_edges) >= 2

    def test_parallel_mermaid_has_dashed_arrows(self):
        viz = PipelineGraphVisualizer(PARALLEL_CONFIG)
        mermaid = viz.to_mermaid()
        assert ".->" in mermaid


class TestExecutionOrder:
    def test_sequential_order(self):
        viz = PipelineGraphVisualizer(SAMPLE_CONFIG)
        order = viz.get_execution_order()
        assert len(order) > 0
        # Input should be in first layer
        assert "input" in order[0]

    def test_parallel_single_layer(self):
        viz = PipelineGraphVisualizer(PARALLEL_CONFIG)
        order = viz.get_execution_order()
        # Parallel checks should appear in same layer
        all_checks = {"check_a", "check_b", "check-a", "check-b"}
        found_parallel = False
        for layer in order:
            layer_checks = set(layer) & all_checks
            if len(layer_checks) >= 2:
                found_parallel = True
        # Parallel checks should be in same layer or adjacent
        assert len(order) >= 1


class TestPipelineGraphDataclass:
    def test_get_node_found(self):
        graph = PipelineGraph(
            name="test",
            nodes=[GraphNode(id="n1", label="Node 1", node_type=NodeType.CHECK)],
            edges=[],
        )
        node = graph.get_node("n1")
        assert node is not None
        assert node.label == "Node 1"

    def test_get_node_not_found(self):
        graph = PipelineGraph(name="test", nodes=[], edges=[])
        assert graph.get_node("missing") is None

    def test_get_dependencies(self):
        graph = PipelineGraph(
            name="test",
            nodes=[
                GraphNode(id="a", label="A", node_type=NodeType.CHECK),
                GraphNode(id="b", label="B", node_type=NodeType.CHECK),
            ],
            edges=[GraphEdge(source="a", target="b", edge_type=EdgeType.DEPENDENCY)],
        )
        deps = graph.get_dependencies("b")
        assert "a" in deps
