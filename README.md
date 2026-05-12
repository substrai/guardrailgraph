# GuardrailGraph

> **Composable AI safety pipeline framework** — define guardrails as a DAG of checks that work across any LLM provider, with industry-specific compliance packs for HIPAA, SOX, GDPR, and FedRAMP.

[![PyPI](https://img.shields.io/pypi/v/substrai-guardrailgraph)](https://pypi.org/project/substrai-guardrailgraph/)
[![npm](https://img.shields.io/npm/v/substrai-guardrailgraph)](https://www.npmjs.com/package/substrai-guardrailgraph)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Why GuardrailGraph?

Every enterprise deploying LLMs needs guardrails. Current options are either provider-locked (Bedrock Guardrails), complex (NeMo Guardrails), or limited (Guardrails AI). GuardrailGraph is the first framework that combines:

- **Composable DAG execution** — checks run in parallel for low latency
- **Provider agnostic** — works with Bedrock, OpenAI, Anthropic, or any LLM
- **Industry compliance packs** — HIPAA, SOX, GDPR out of the box
- **Serverless-native** — designed for AWS Lambda from day one
- **Simple API** — `@check` decorator + `pipeline()` builder

## Installation

```bash
# Python
pip install substrai-guardrailgraph

# npm (TypeScript/JavaScript)
npm install substrai-guardrailgraph
```

## Quick Start

### 5-Minute Setup

```python
from guardrailgraph import pipeline, check, Action
from guardrailgraph.checks import pii_check, toxicity_check, injection_check

# Create a pipeline with built-in checks
my_pipeline = pipeline(
    name="my-app",
    checks=[
        pii_check(action=Action.REDACT),
        toxicity_check(threshold=0.7),
        injection_check(),
    ],
    mode="fail-closed",
)

# Run guardrails on any text
result = my_pipeline.run("User input here")

if result.allowed:
    # Safe to forward to LLM
    text = result.modified_text or "User input here"
else:
    # Content blocked
    print(f"Blocked: {result.action.value}")
```

### Custom Checks

```python
from guardrailgraph import check, Action

@check(name="profanity", action=Action.BLOCK, threshold=0.7)
def check_profanity(text: str) -> dict:
    """Custom profanity detection."""
    bad_words = ["badword1", "badword2"]
    found = [w for w in bad_words if w in text.lower()]
    return {
        "detected": len(found) > 0,
        "confidence": min(len(found) / 2.0, 1.0),
        "matched": found,
    }
```

### Industry Compliance Packs

```python
from guardrailgraph import pipeline
from guardrailgraph.packs import hipaa, financial

# HIPAA-compliant healthcare chatbot
healthcare = pipeline(
    name="patient-assistant",
    packs=[hipaa.full()],
)

# SOX-compliant financial advisor
finance = pipeline(
    name="investment-advisor",
    packs=[financial.sox()],
    mode="fail-closed",
)
```

### Middleware Integration

```python
from guardrailgraph.middleware import guardrail

@guardrail(pipeline=my_pipeline)
def call_llm(prompt: str) -> str:
    """Your LLM call — automatically wrapped with guardrails."""
    import boto3
    client = boto3.client("bedrock-runtime")
    # ... invoke model ...
    return response
```

## YAML Configuration

```yaml
# guardrailgraph.yaml
project:
  name: "my-app-guardrails"
  version: "1.0.0"

pipeline:
  mode: fail-closed
  timeout_ms: 500
  parallel: true

checks:
  - name: pii-detection
    type: builtin/pii
    action: redact
    config:
      entity_types: [SSN, PHONE, EMAIL, CREDIT_CARD]

  - name: toxicity
    type: builtin/toxicity
    action: block
    config:
      threshold: 0.7

  - name: prompt-injection
    type: builtin/injection
    action: block
    config:
      sensitivity: high
```

## CLI

```bash
# Scaffold a new project
guardrailgraph init my-project
guardrailgraph init my-project --pack hipaa

# Development
guardrailgraph dev          # Interactive testing
guardrailgraph test         # Run tests
guardrailgraph test --adversarial  # Adversarial suite
guardrailgraph validate     # Validate config
```

## Built-in Checks

| Check | Description | Default Action |
|-------|-------------|----------------|
| `pii_check()` | Detects SSN, phone, email, credit card, IP | REDACT |
| `toxicity_check()` | Scores hate, violence, sexual, self-harm | BLOCK |
| `topic_check()` | Block/allow specific topics | BLOCK |
| `injection_check()` | Prompt injection defense | BLOCK |
| `cost_check()` | Token/cost limits per request | BLOCK |

## Architecture

```
Input → [Check 1] ──→ [Check 2] ──→ [Check 3]
         (parallel)    (parallel)    (parallel)
              ↓              ↓              ↓
         [PASS/BLOCK/REDACT/FLAG_FOR_REVIEW]
              ↓
         [Final Decision + Audit Log]
```

Checks execute as a **DAG** (directed acyclic graph). Independent checks run in parallel for minimum latency. Dependent checks run sequentially.

## Integration with LambdaLLM

```python
from lambdallm import handler, Model
from guardrailgraph import pipeline
from guardrailgraph.packs import hipaa

@handler(
    model=Model.CLAUDE_3_SONNET,
    guardrails=pipeline(packs=[hipaa.full()]),
)
def lambda_handler(event, context):
    return context.invoke("Answer: {q}", q=event["body"]["question"])
```

## Comparison

| Feature | Bedrock Guardrails | NeMo | Guardrails AI | **GuardrailGraph** |
|---------|-------------------|------|---------------|-------------------|
| Provider agnostic | ❌ | ❌ | Partial | ✅ |
| Composable DAG | ❌ | ❌ | ❌ | ✅ |
| Industry packs | ❌ | ❌ | ❌ | ✅ |
| Serverless-native | Managed | ❌ | ❌ | ✅ |
| Custom checks | Limited | Complex | Yes | ✅ Simple |
| Open source | ❌ | ✅ | ✅ | ✅ MIT |

## License

MIT © [Gaurav Kumar Sinha](https://github.com/substrai)
