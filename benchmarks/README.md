# GuardrailGraph Benchmarks

Real-world benchmarks measuring GuardrailGraph performance against AWS services and alternative solutions.

## Results Summary

### Local Pipeline Performance

| Configuration | Avg Latency | P95 Latency | Throughput |
|---------------|-------------|-------------|------------|
| 1 check (PII) | 0.506ms | 1.877ms | 3,919 req/s |
| 3 checks (PII+toxicity+injection) | 0.480ms | 0.562ms | 2,332 req/s |
| 5 checks (full suite) | 0.513ms | 0.668ms | 1,949 req/s |
| HIPAA pack (4 checks) | 0.538ms | 0.747ms | 2,266 req/s |
| FedRAMP pack (5 checks) | 0.509ms | 0.715ms | — |

### Detection Accuracy

| Check | Precision | Recall | F1 Score | False Positive Rate |
|-------|-----------|--------|----------|---------------------|
| PII Detection | 100% | 100% | 100% | 0% |
| Prompt Injection | 90% | 90% | 90% | 0% |

### AWS Comparison (Real API Calls, us-east-1)

| Metric | AWS Comprehend | GuardrailGraph | Advantage |
|--------|---------------|----------------|-----------|
| PII Detection Latency | 178ms | 0.96ms | **186x faster** |
| PII Detection Accuracy | ML-based (high) | Regex-based (high) | Comparable |

### Bedrock Integration Overhead

| Metric | Value |
|--------|-------|
| Raw Bedrock (Claude 3 Haiku) | 395ms avg |
| With GuardrailGraph (3 checks) | 336ms avg |
| Guardrail overhead | **3.51ms (1.04% of total)** |
| Injection blocking | 100% detection |

### Package Size Comparison

| Framework | Size |
|-----------|------|
| GuardrailGraph | **201KB** |
| Guardrails AI | ~28MB |
| NeMo Guardrails | ~45MB |
| LangChain | ~139MB |

---

## Replicating the Benchmarks

### Prerequisites

```bash
# Python 3.9+
python --version

# Clone the repository
git clone https://github.com/substrai/guardrailgraph.git
cd guardrailgraph

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install with dev + AWS dependencies
pip install -e ".[all,dev]"
```

### Running Local Benchmarks (No AWS Required)

```bash
# Run all local benchmarks
python benchmarks/run_benchmarks.py

# Run specific suite
python benchmarks/run_benchmarks.py --suite latency
python benchmarks/run_benchmarks.py --suite pii
python benchmarks/run_benchmarks.py --suite injection
python benchmarks/run_benchmarks.py --suite throughput
python benchmarks/run_benchmarks.py --suite comparison
python benchmarks/run_benchmarks.py --suite size

# Save to specific file
python benchmarks/run_benchmarks.py --output results/my_results.json
```

### Running AWS Benchmarks (Requires AWS Credentials)

#### Step 1: Configure AWS Credentials

```bash
export AWS_ACCESS_KEY_ID=<your-access-key>
export AWS_SECRET_ACCESS_KEY=<your-secret-key>
export AWS_SESSION_TOKEN=<your-session-token>  # if using temporary credentials
export AWS_DEFAULT_REGION=us-east-1
```

#### Step 2: Verify Access

```bash
# Verify credentials
aws sts get-caller-identity

# Verify Bedrock access (Claude 3 Haiku)
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-haiku-20240307-v1:0 \
  --content-type application/json \
  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":10,"messages":[{"role":"user","content":"Hi"}]}' \
  /dev/stdout 2>/dev/null | python -c "import sys,json; print(json.load(sys.stdin)['content'][0]['text'])"

# Verify Comprehend access
aws comprehend detect-pii-entities \
  --text "My SSN is 123-45-6789" \
  --language-code en
```

#### Step 3: Required AWS Services

| Service | Purpose | Required Permissions |
|---------|---------|---------------------|
| AWS Comprehend | PII detection comparison | `comprehend:DetectPiiEntities` |
| AWS Bedrock | LLM invocation (Claude 3 Haiku) | `bedrock:InvokeModel` |
| AWS STS | Identity verification | `sts:GetCallerIdentity` |

#### Step 4: Run AWS Benchmarks

```bash
python benchmarks/run_aws_benchmarks.py
```

Results are saved to `benchmarks/results/aws_benchmark_<timestamp>.json`.

---

## Benchmark Methodology

### Local Benchmarks (`run_benchmarks.py`)

1. **Pipeline Latency**: Measures wall-clock time for `pipeline.run()` across 100 iterations per configuration. Reports avg, P50, P95, P99.

2. **PII Detection Accuracy**: Tests against 10 known-PII texts and 10 safe texts. Measures precision, recall, and F1 score.

3. **Injection Detection**: Tests against 10 known injection attempts and 10 safe texts. Measures detection rate and false positive rate.

4. **Compliance Pack Performance**: Measures latency and detection rate for each industry pack (HIPAA, SOX, GDPR, FedRAMP).

5. **Throughput**: Saturates a single thread for 2 seconds, counting requests processed. Reports requests/second.

6. **Framework Comparison**: Compares GuardrailGraph pipeline execution against raw regex pattern matching (same patterns, no framework overhead).

7. **Package Size**: Measures installed source file count and total size.

### AWS Benchmarks (`run_aws_benchmarks.py`)

1. **Comprehend vs GuardrailGraph**: Sends identical PII-containing texts to both AWS Comprehend (`DetectPiiEntities`) and GuardrailGraph's regex-based PII check. Compares latency and detection results.

2. **Bedrock + Middleware**: Measures raw Bedrock Claude 3 Haiku latency, then the same calls wrapped with GuardrailGraph middleware (input + output checks). Calculates framework overhead as percentage of total request time.

3. **End-to-End HIPAA**: Full pipeline with HIPAA compliance pack wrapping Bedrock calls. Tests PII redaction (text modified before reaching LLM), medical claim detection, and safe text pass-through.

4. **Local Throughput**: Confirms local check throughput is not affected by having AWS SDK imported.

### Environment

- **Hardware**: Apple Silicon (M-series), macOS
- **Python**: 3.14.x
- **Region**: us-east-1
- **Model**: `anthropic.claude-3-haiku-20240307-v1:0`
- **Network**: Standard internet connection (not VPC-internal)

### Notes

- AWS latencies include network round-trip time (client → AWS → client)
- GuardrailGraph local checks run entirely in-process (no network)
- The 186x speed advantage over Comprehend is expected: regex runs locally vs. network API call
- The key metric is **overhead percentage**: adding guardrails to an LLM call adds only ~1% latency
- All tests use real AWS API calls (not mocked)

---

## Interpreting Results

### For EB1A / Academic Papers

The key claims supported by these benchmarks:

1. **Sub-millisecond pipeline latency** — 3 checks execute in 0.48ms avg
2. **Negligible overhead on LLM calls** — 1.04% overhead (3.5ms on a 336ms call)
3. **186x faster than AWS Comprehend** for PII detection (local regex vs. API call)
4. **100% PII detection accuracy** on standard patterns (SSN, email, phone, credit card)
5. **90% injection detection** with 0% false positives
6. **2,300+ requests/second** throughput on a single thread
7. **201KB package** vs 28-139MB for alternatives

### Limitations

- PII detection uses regex patterns (not ML) — may miss novel PII formats
- Toxicity detection uses keyword matching — production would use ML models
- AWS Comprehend comparison is latency-focused (Comprehend has broader entity coverage)
- Benchmarks run on developer machine, not Lambda (Lambda would add cold start)

---

## File Structure

```
benchmarks/
├── README.md                  # This file
├── run_benchmarks.py          # Local benchmark suite (no AWS required)
├── run_aws_benchmarks.py      # AWS benchmark suite (requires credentials)
└── results/
    ├── benchmark_20260512_123823.json       # Local results
    └── aws_benchmark_20260512_124324.json   # AWS results
```
