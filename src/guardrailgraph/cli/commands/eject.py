"""guardrailgraph eject — export raw infrastructure templates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


CDK_TEMPLATE = """\
\"\"\"GuardrailGraph CDK Stack — ejected from guardrailgraph.yaml.

This is a standalone CDK stack. Modify freely.
\"\"\"

from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_lambda as lambda_,
    aws_dynamodb as dynamodb,
    aws_sns as sns,
    aws_cloudwatch as cloudwatch,
    aws_apigateway as apigw,
)
from constructs import Construct


class GuardrailGraphStack(Stack):
    def __init__(self, scope: Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # Audit Trail Table
        self.audit_table = dynamodb.Table(
            self, "AuditTable",
            table_name="guardrailgraph-audit-{pipeline_name}",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="sk", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.RETAIN,
            time_to_live_attribute="ttl",
        )

        # Alert Topic
        self.alert_topic = sns.Topic(
            self, "AlertTopic",
            topic_name="guardrailgraph-alerts-{pipeline_name}",
        )

        # Lambda Function
        self.guardrail_function = lambda_.Function(
            self, "GuardrailFunction",
            function_name="guardrailgraph-{pipeline_name}",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("./src"),
            timeout=Duration.seconds(30),
            memory_size=256,
            environment={{
                "PIPELINE_NAME": "{pipeline_name}",
                "AUDIT_TABLE": self.audit_table.table_name,
                "ALERT_TOPIC_ARN": self.alert_topic.topic_arn,
            }},
        )

        # Grant permissions
        self.audit_table.grant_read_write_data(self.guardrail_function)
        self.alert_topic.grant_publish(self.guardrail_function)

        # API Gateway
        self.api = apigw.RestApi(
            self, "GuardrailApi",
            rest_api_name="guardrailgraph-{pipeline_name}",
        )
        check_resource = self.api.root.add_resource("check")
        check_resource.add_method(
            "POST",
            apigw.LambdaIntegration(self.guardrail_function),
        )

        # CloudWatch Dashboard
        self.dashboard = cloudwatch.Dashboard(
            self, "Dashboard",
            dashboard_name="guardrailgraph-{pipeline_name}",
        )
        self.dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Invocations",
                left=[self.guardrail_function.metric_invocations()],
            ),
            cloudwatch.GraphWidget(
                title="Errors",
                left=[self.guardrail_function.metric_errors()],
            ),
            cloudwatch.GraphWidget(
                title="Duration",
                left=[self.guardrail_function.metric_duration()],
            ),
        )
"""


def run(args: Any) -> int:
    """Eject infrastructure templates for full control."""
    from guardrailgraph.core.config import load_config

    config_path = getattr(args, "config", "guardrailgraph.yaml")
    output_format = getattr(args, "format", "cdk")

    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"Config not found: {config_path}")
        return 1

    project_config = config.get("project", {})
    pipeline_name = project_config.get("name", "default").replace(" ", "-")

    output_dir = Path("infrastructure-ejected")
    output_dir.mkdir(exist_ok=True)

    print(f"Ejecting infrastructure for: {pipeline_name}")
    print(f"Format: {output_format}")

    if output_format == "cdk":
        cdk_content = CDK_TEMPLATE.format(pipeline_name=pipeline_name)
        cdk_path = output_dir / "cdk_stack.py"
        cdk_path.write_text(cdk_content)
        print(f"  ✓ Generated: {cdk_path}")

        # CDK app
        app_content = f'''\
import aws_cdk as cdk
from cdk_stack import GuardrailGraphStack

app = cdk.App()
GuardrailGraphStack(app, "GuardrailGraph-{pipeline_name}")
app.synth()
'''
        app_path = output_dir / "app.py"
        app_path.write_text(app_content)
        print(f"  ✓ Generated: {app_path}")

        # Requirements
        req_path = output_dir / "requirements.txt"
        req_path.write_text("aws-cdk-lib>=2.100.0\nconstructs>=10.0.0\nsubstrai-guardrailgraph>=0.2.0\n")
        print(f"  ✓ Generated: {req_path}")

    print(f"\n✅ Ejected to: {output_dir}/")
    print(f"   You now have full control over the infrastructure.")
    print(f"   Modify freely — GuardrailGraph CLI will no longer manage these resources.")

    return 0
