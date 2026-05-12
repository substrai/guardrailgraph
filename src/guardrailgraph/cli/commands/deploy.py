"""guardrailgraph deploy — deploy guardrail infrastructure to AWS."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict


SAM_TEMPLATE = """\
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: GuardrailGraph Pipeline - {pipeline_name}

Globals:
  Function:
    Timeout: 30
    Runtime: python3.11
    MemorySize: 256
    Environment:
      Variables:
        PIPELINE_NAME: {pipeline_name}
        PIPELINE_MODE: {mode}

Resources:
  GuardrailFunction:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: guardrailgraph-{pipeline_name}
      Handler: handler.lambda_handler
      CodeUri: ./src/
      Description: GuardrailGraph pipeline - {pipeline_name}
      Policies:
        - DynamoDBCrudPolicy:
            TableName: !Ref AuditTable
        - ComprehendReadOnly
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /check
            Method: post

  AuditTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: guardrailgraph-audit-{pipeline_name}
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
        - AttributeName: sk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
        - AttributeName: sk
          KeyType: RANGE
      TimeToLiveSpecification:
        AttributeName: ttl
        Enabled: true

  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: guardrailgraph-alerts-{pipeline_name}

  Dashboard:
    Type: AWS::CloudWatch::Dashboard
    Properties:
      DashboardName: guardrailgraph-{pipeline_name}
      DashboardBody: '{dashboard_body}'

Outputs:
  ApiEndpoint:
    Description: API Gateway endpoint URL
    Value: !Sub "https://${{ServerlessRestApi}}.execute-api.${{AWS::Region}}.amazonaws.com/Prod/check"
  AuditTableName:
    Description: DynamoDB audit table
    Value: !Ref AuditTable
  AlertTopicArn:
    Description: SNS alert topic ARN
    Value: !Ref AlertTopic
"""

HANDLER_TEMPLATE = """\
\"\"\"Lambda handler for GuardrailGraph pipeline.\"\"\"

import json
import os

from guardrailgraph.core.config import load_pipeline


# Load pipeline at module level (cached across invocations)
PIPELINE = load_pipeline(os.environ.get("CONFIG_PATH", "guardrailgraph.yaml"))


def lambda_handler(event, context):
    \"\"\"Process a guardrail check request.\"\"\"
    body = json.loads(event.get("body", "{}"))
    text = body.get("text", "")

    if not text:
        return {
            "statusCode": 400,
            "body": json.dumps({"error": "Missing 'text' field"}),
        }

    result = PIPELINE.run(text, metadata=body.get("metadata"))

    return {
        "statusCode": 200,
        "body": json.dumps({
            "allowed": result.allowed,
            "action": result.action.value,
            "modified_text": result.modified_text,
            "checks": [
                {
                    "name": r.name,
                    "detected": r.detected,
                    "confidence": r.confidence,
                    "action": r.action.value,
                }
                for r in result.check_results
            ],
            "latency_ms": result.total_latency_ms,
        }),
    }
"""


def run(args: Any) -> int:
    """Execute the deploy command."""
    from guardrailgraph.core.config import load_config, build_pipeline_from_config

    config_path = getattr(args, "config", "guardrailgraph.yaml")
    env = getattr(args, "env", "dev")
    dry_run = getattr(args, "dry_run", False)

    print(f"Deploying GuardrailGraph pipeline...")
    print(f"  Config: {config_path}")
    print(f"  Environment: {env}")

    # Load and validate config
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"  ✗ Config not found: {config_path}")
        return 1

    pipeline_config = config.get("pipeline", {})
    project_config = config.get("project", {})
    pipeline_name = project_config.get("name", "default").replace(" ", "-")
    mode = pipeline_config.get("mode", "fail-closed")

    # Build pipeline to validate
    try:
        pipeline = build_pipeline_from_config(config, environment=env)
        print(f"  ✓ Pipeline validated: {len(pipeline.checks)} checks")
    except Exception as e:
        print(f"  ✗ Pipeline validation failed: {e}")
        return 1

    # Generate infrastructure
    output_dir = Path("infrastructure")
    output_dir.mkdir(exist_ok=True)

    # Generate SAM template
    dashboard_body = json.dumps({"widgets": []}).replace('"', '\\"')
    sam_content = SAM_TEMPLATE.format(
        pipeline_name=pipeline_name,
        mode=mode,
        dashboard_body=dashboard_body,
    )
    sam_path = output_dir / "template.yaml"
    sam_path.write_text(sam_content)
    print(f"  ✓ Generated: {sam_path}")

    # Generate handler
    src_dir = output_dir / "src"
    src_dir.mkdir(exist_ok=True)
    handler_path = src_dir / "handler.py"
    handler_path.write_text(HANDLER_TEMPLATE)
    print(f"  ✓ Generated: {handler_path}")

    # Copy config
    import shutil
    config_dest = src_dir / "guardrailgraph.yaml"
    shutil.copy2(config_path, config_dest)
    print(f"  ✓ Copied config: {config_dest}")

    if dry_run:
        print(f"\n  [DRY RUN] Infrastructure generated but not deployed.")
        print(f"  To deploy manually:")
        print(f"    sam build -t {sam_path}")
        print(f"    sam deploy --guided")
        return 0

    print(f"\n  Infrastructure generated in: {output_dir}/")
    print(f"\n  Deploy with:")
    print(f"    sam build -t {sam_path}")
    print(f"    sam deploy --stack-name guardrailgraph-{pipeline_name} --capabilities CAPABILITY_IAM")

    return 0
