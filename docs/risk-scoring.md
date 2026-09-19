# Risk-scoring methodology

**Goals:** deterministic, explainable, bounded (0–100), integer-only, and independent of any LLM.

## Formula

```
score       = min(100, Σ risk_weight(finding))          # one finding per (rule, resource)
score_band  = 0 → secure | 1–19 → low | 20–39 → medium | 40–69 → high | 70–100 → critical
risk_level  = score_band, raised to at least "high" if any finding is CRITICAL
```

### Weights (owned by each rule)

| Severity | Weight | Rules |
|---|---|---|
| Critical | 30 | AWS-S3-001, AWS-EC2-001, AWS-EC2-002, AZ-NSG-001 |
| High | 20 | AWS-S3-002, AWS-EC2-003, AWS-RDS-001, AZ-STOR-001 |
| Medium | 10 | AWS-S3-003, AWS-ENC-001 |
| Low | 4 | (no rule yet; reserved) |

**Why 30/20/10?** Three critical findings (90) or a critical plus a high and a medium (60) already land in the
*critical/high* bands; the ratios keep "one severe exposure outranks several hygiene issues" without exotic maths.

## Why escalation exists

One public S3 bucket scores 30, which is only the *medium* band. That would understate a data-exposure incident, so
any CRITICAL finding lifts the **level** to at least *high* (the numeric score is unchanged and the response says
`escalated: true`). This keeps the number honest and the label safe.

## Why a cap

The sum saturates at 100 so the scale stays comparable. `cap_applied` and `raw_total` are always returned, so you can
still see how far past 100 a scan went (e.g. `raw_total: 210`).

## What the API returns

```jsonc
"score_breakdown": {
  "method": "Score = sum of the risk weight of every finding …",
  "raw_total": 210, "score": 100, "cap": 100, "cap_applied": true,
  "score_band": "critical", "risk_level": "critical", "escalated": false,
  "by_severity":  [{"severity": "critical", "count": 4, "points": 120}, …],
  "contributions": [{"rule_id": "AWS-S3-001", "resource_name": "aws_s3_bucket.public_assets",
                     "severity": "critical", "points": 30}, …],
  "bands": {"0": "secure", "1-19": "low", "20-39": "medium", "40-69": "high", "70-100": "critical"}
}
```

`Σ contributions.points == raw_total` always holds (asserted in tests). The dashboard renders this as **Why this
score?** with a per-severity table and a per-finding table.

## Worked examples (all reproducible with the bundled samples)

| Input | Findings | Raw | Score | Level |
|---|---|---|---|---|
| `terraform/safe.tf` | none | 0 | 0 | secure |
| one SSH-open security group | 1 critical | 30 | 30 | **high** (escalated from medium) |
| `cloudformation/vulnerable.yaml` | 2 critical + 1 medium | 70 | 70 | critical |
| `terraform/vulnerable.tf` | 4 critical + 3 high + 3 medium | 210 | 100 | critical (cap applied) |

## Dashboard "overall" score

`overall = round(mean(scan scores))`, shown next to the latest and highest scan scores. It is a portfolio indicator;
the per-scan score is the authoritative one.

## Properties verified by tests

Determinism · order-independence · bounds (0–100, integer) · every band boundary (0,1,19,20,39,40,69,70,100) ·
escalation · cap · contributions sum to the raw total.

## Known trade-offs

* Weights are per rule, not per resource sensitivity (a public *log* bucket scores like a public *customer-data* bucket).
* Counting is per (rule, resource), so ten volumes without encryption score ten times the same rule.
* No exploitability or blast-radius modelling — deliberately, to keep the score explainable.
