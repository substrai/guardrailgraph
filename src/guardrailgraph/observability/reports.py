"""Compliance report generation — auto-generate evidence for auditors.

Generates reports in JSON and text formats documenting:
- Pipeline configuration and check inventory
- Execution statistics (block rates, detection rates)
- Audit trail summary
- Compliance posture assessment
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from guardrailgraph.core.pipeline import Pipeline
from guardrailgraph.core.result import PipelineResult
from guardrailgraph.observability.analytics import GuardrailAnalytics


@dataclass
class ComplianceReport:
    """A generated compliance report."""

    title: str
    framework: str  # HIPAA, SOX, GDPR, FedRAMP
    generated_at: float = field(default_factory=time.time)
    period_start: Optional[float] = None
    period_end: Optional[float] = None
    pipeline_name: str = ""
    summary: Dict[str, Any] = field(default_factory=dict)
    checks_inventory: List[Dict[str, Any]] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliance_status: str = "compliant"  # compliant, non_compliant, needs_review

    def to_json(self) -> str:
        """Export report as JSON."""
        return json.dumps({
            "title": self.title,
            "framework": self.framework,
            "generated_at": self.generated_at,
            "period": {
                "start": self.period_start,
                "end": self.period_end,
            },
            "pipeline_name": self.pipeline_name,
            "compliance_status": self.compliance_status,
            "summary": self.summary,
            "checks_inventory": self.checks_inventory,
            "statistics": self.statistics,
            "findings": self.findings,
            "recommendations": self.recommendations,
        }, indent=2)

    def to_text(self) -> str:
        """Export report as formatted text."""
        lines = [
            f"{'=' * 60}",
            f"COMPLIANCE REPORT: {self.title}",
            f"{'=' * 60}",
            f"Framework: {self.framework}",
            f"Pipeline: {self.pipeline_name}",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.generated_at))}",
            f"Status: {self.compliance_status.upper()}",
            "",
            f"{'─' * 60}",
            "SUMMARY",
            f"{'─' * 60}",
        ]

        for key, value in self.summary.items():
            lines.append(f"  {key}: {value}")

        lines.extend([
            "",
            f"{'─' * 60}",
            "CHECKS INVENTORY",
            f"{'─' * 60}",
        ])

        for check_info in self.checks_inventory:
            lines.append(f"  • {check_info['name']} ({check_info['action']}) — {check_info.get('description', 'N/A')}")

        lines.extend([
            "",
            f"{'─' * 60}",
            "STATISTICS",
            f"{'─' * 60}",
        ])

        for key, value in self.statistics.items():
            if isinstance(value, float):
                lines.append(f"  {key}: {value:.4f}")
            else:
                lines.append(f"  {key}: {value}")

        if self.findings:
            lines.extend([
                "",
                f"{'─' * 60}",
                "FINDINGS",
                f"{'─' * 60}",
            ])
            for i, finding in enumerate(self.findings, 1):
                lines.append(f"  {i}. [{finding.get('severity', 'INFO')}] {finding.get('description', '')}")

        if self.recommendations:
            lines.extend([
                "",
                f"{'─' * 60}",
                "RECOMMENDATIONS",
                f"{'─' * 60}",
            ])
            for i, rec in enumerate(self.recommendations, 1):
                lines.append(f"  {i}. {rec}")

        lines.append(f"\n{'=' * 60}")
        lines.append("END OF REPORT")
        lines.append(f"{'=' * 60}")

        return "\n".join(lines)


class ReportGenerator:
    """Generates compliance reports from pipeline analytics.

    Args:
        pipeline: The pipeline to report on.
        analytics: Analytics engine with collected metrics.
        framework: Compliance framework (HIPAA, SOX, GDPR, FedRAMP).

    Example:
        generator = ReportGenerator(
            pipeline=my_pipeline,
            analytics=my_analytics,
            framework="HIPAA",
        )
        report = generator.generate()
        print(report.to_text())
    """

    def __init__(
        self,
        pipeline: Pipeline,
        analytics: Optional[GuardrailAnalytics] = None,
        framework: str = "general",
    ):
        self.pipeline = pipeline
        self.analytics = analytics
        self.framework = framework

    def generate(
        self,
        period_start: Optional[float] = None,
        period_end: Optional[float] = None,
    ) -> ComplianceReport:
        """Generate a compliance report.

        Args:
            period_start: Report period start (epoch seconds).
            period_end: Report period end (epoch seconds).

        Returns:
            ComplianceReport instance.
        """
        now = time.time()
        period_end = period_end or now
        period_start = period_start or (now - 86400 * 30)  # Default: last 30 days

        report = ComplianceReport(
            title=f"{self.framework} Compliance Report — {self.pipeline.name}",
            framework=self.framework,
            period_start=period_start,
            period_end=period_end,
            pipeline_name=self.pipeline.name,
        )

        # Checks inventory
        report.checks_inventory = [
            {
                "name": c.name,
                "action": c.action.value,
                "threshold": c.threshold,
                "description": c.description,
                "tags": c.tags,
            }
            for c in self.pipeline.checks
        ]

        # Summary
        report.summary = {
            "pipeline_mode": self.pipeline.mode,
            "total_checks": len(self.pipeline.checks),
            "framework": self.framework,
            "parallel_execution": self.pipeline.parallel,
        }

        # Statistics from analytics
        if self.analytics:
            analytics_summary = self.analytics.summary()
            report.statistics = {
                "total_requests_processed": analytics_summary["total_requests"],
                "total_blocked": analytics_summary["blocked"],
                "total_passed": analytics_summary["passed"],
                "block_rate": analytics_summary["block_rate"],
                "avg_latency_ms": analytics_summary["avg_latency_ms"],
                "p95_latency_ms": analytics_summary["p95_latency_ms"],
            }

            # Add per-check stats
            for check_name, check_stats in analytics_summary.get("checks", {}).items():
                report.statistics[f"check_{check_name}_detection_rate"] = check_stats["detection_rate"]
                report.statistics[f"check_{check_name}_false_positive_rate"] = check_stats["false_positive_rate"]

        # Compliance assessment
        report.compliance_status = self._assess_compliance(report)
        report.findings = self._generate_findings(report)
        report.recommendations = self._generate_recommendations(report)

        return report

    def _assess_compliance(self, report: ComplianceReport) -> str:
        """Assess overall compliance status."""
        # Check if required checks are present for the framework
        required_checks = self._get_required_checks()
        present_checks = {c["name"] for c in report.checks_inventory}

        missing = required_checks - present_checks
        if missing:
            return "non_compliant"

        # Check if block rate is reasonable (not too high = false positives)
        block_rate = report.statistics.get("block_rate", 0)
        if block_rate > 0.5:
            return "needs_review"

        return "compliant"

    def _get_required_checks(self) -> set:
        """Get required checks for the compliance framework."""
        requirements = {
            "HIPAA": {"phi-detection", "hipaa-audit-log"},
            "SOX": {"financial-advice-detection", "sox-audit-log"},
            "GDPR": {"personal-data-detection", "data-subject-rights", "gdpr-audit-log"},
            "FedRAMP": {"classification-detection", "fedramp-audit-log"},
        }
        return requirements.get(self.framework, set())

    def _generate_findings(self, report: ComplianceReport) -> List[Dict[str, Any]]:
        """Generate compliance findings."""
        findings = []

        # Check for missing required checks
        required = self._get_required_checks()
        present = {c["name"] for c in report.checks_inventory}
        missing = required - present

        for check_name in missing:
            findings.append({
                "severity": "HIGH",
                "description": f"Required check '{check_name}' is not configured",
                "remediation": f"Add '{check_name}' to the pipeline configuration",
            })

        # Check for high false positive rates
        for key, value in report.statistics.items():
            if "false_positive_rate" in key and value > 0.1:
                check_name = key.replace("check_", "").replace("_false_positive_rate", "")
                findings.append({
                    "severity": "MEDIUM",
                    "description": f"Check '{check_name}' has high false positive rate ({value:.1%})",
                    "remediation": "Review and adjust threshold or detection logic",
                })

        return findings

    def _generate_recommendations(self, report: ComplianceReport) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []

        if report.compliance_status == "non_compliant":
            recommendations.append("Add all required checks for the compliance framework")

        if report.statistics.get("block_rate", 0) > 0.3:
            recommendations.append("Review block rate — may indicate overly aggressive thresholds")

        if report.statistics.get("avg_latency_ms", 0) > 200:
            recommendations.append("Pipeline latency exceeds 200ms — consider optimizing check execution")

        if not any("audit" in c["name"] for c in report.checks_inventory):
            recommendations.append("Add audit logging for compliance evidence")

        return recommendations
