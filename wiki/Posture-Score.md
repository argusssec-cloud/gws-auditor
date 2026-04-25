# Posture Score

The posture score is a 0-100 metric that provides a single-number summary of your Google Workspace security posture. Unlike the pass rate (which treats all checks equally), the posture score weights findings by severity so that critical misconfigurations have a much larger impact than low-severity ones.

## Quick Reference

| Score | Grade | Meaning |
|------:|:-----:|---------|
| 90-100 | **A** | Excellent — minimal risk, well-hardened |
| 80-89 | **B** | Good — minor gaps, low overall risk |
| 70-79 | **C** | Fair — notable gaps, moderate risk |
| 50-69 | **D** | Poor — significant gaps, high risk |
| 0-49 | **F** | Critical — severe misconfigurations requiring immediate action |

## Formula

The score is computed per severity tier, then aggregated:

```
For each severity tier T with at least one scored check:

    weight(T)    = { CRITICAL: 8, HIGH: 6, MEDIUM: 3, LOW: 2 }
    penalty_w(T) = weight(T)²  for CRITICAL  (= 64)
                   weight(T)   for all others

    tier_penalty = (fails × penalty_w) + (warns × penalty_w × 0.5)
    tier_max     = scored_count(T) × penalty_w

score = max(0, round((1 - total_penalty / total_max) × 100))
```

### Key design decisions

- **Critical findings are squared** (weight 8 → penalty weight 64). A single critical failure will heavily drag down the score, reflecting the outsized business risk.
- **Warnings count as half a failure.** A WARN result contributes 50% of the penalty of a FAIL, recognizing it as a soft failure.
- **Empty tiers are excluded.** If your tenant has no CRITICAL-severity checks that apply (e.g., due to license gating), the critical tier doesn't inflate or deflate the denominator.
- **Only scored checks participate.** Inventory checks (ADD-28 through ADD-39) are tagged `scored=False` and do not affect the score. ERROR, MANUAL, and NOT_APPLICABLE results are also excluded.
- **Muting improves the score.** When you override a finding to PASS via the dashboard (accept risk), it counts as PASS for scoring.

## Examples

### Example 1: Small tenant, one critical failure

| Tier | Checks | Passed | Failed | Warned |
|------|-------:|-------:|-------:|-------:|
| CRITICAL | 2 | 1 | 1 | 0 |
| MEDIUM | 10 | 10 | 0 | 0 |

```
Critical: penalty = 1 × 64 = 64,  max = 2 × 64 = 128
Medium:   penalty = 0,             max = 10 × 3 = 30
Total:    penalty = 64,            max = 158
Score:    round((1 - 64/158) × 100) = 59 (D)
```

One critical failure out of 12 checks produces a D grade — the squaring ensures critical issues dominate.

### Example 2: Well-hardened tenant with minor warnings

| Tier | Checks | Passed | Failed | Warned |
|------|-------:|-------:|-------:|-------:|
| CRITICAL | 24 | 24 | 0 | 0 |
| HIGH | 30 | 28 | 0 | 2 |
| MEDIUM | 100 | 95 | 3 | 2 |

```
Critical: penalty = 0,                  max = 24 × 64 = 1536
High:     penalty = 2 × 6 × 0.5 = 6,   max = 30 × 6 = 180
Medium:   penalty = 3×3 + 2×3×0.5 = 12, max = 100 × 3 = 300
Total:    penalty = 18,                  max = 2016
Score:    round((1 - 18/2016) × 100) = 99 (A)
```

## How to Improve Your Score

The score is most sensitive to:

1. **Fix critical failures first.** Each critical failure adds 64 penalty points. Fixing one critical issue improves the score far more than fixing several medium ones.
2. **Address high-severity failures.** Each adds 6 penalty points.
3. **Resolve warnings.** Each warning adds half the penalty of a failure at its tier.
4. **Accept risk for known exceptions.** If a finding is a deliberate configuration choice (e.g., Sites enabled for a specific team), override it to PASS in the dashboard. This counts as PASS for scoring.

### Impact per fix

| Fix | Score impact (approximate) |
|-----|---------------------------|
| Resolve 1 critical failure | +3 to +30 points (depends on total checks) |
| Resolve 1 high failure | +0.3 to +3 points |
| Resolve 1 medium failure | +0.1 to +1.5 points |
| Accept risk on 1 critical | Same as resolving |

## Where the Score Appears

- **CLI output** — in the Audit Summary table
- **JSON report** — `summary.posture_score` and `summary.posture_grade`
- **HTML report** — score card next to Pass Rate
- **Dashboard** — metric card in the Overview page (updates when overrides are applied)
- **AI Analyst** — `get_audit_summary` tool returns score and per-tier breakdown

## Relationship to Pass Rate

| Metric | Formula | Treats all checks equally? | Severity-aware? |
|--------|---------|:-:|:-:|
| **Pass Rate** | passed / (passed + failed + warned) | Yes | No |
| **Posture Score** | Weighted by severity, critical squared | No | Yes |

A tenant could have a 90% pass rate but a 60 posture score if the 10% failures are all critical. The posture score surfaces this risk; the pass rate doesn't.

## Technical Details

- Implementation: `src/gws_auditor/scoring.py`
- Severity weights: `SEVERITY_WEIGHTS` dict
- Grade thresholds: `_GRADE_THRESHOLDS` list
- Scored flag: `@check(..., scored=True)` decorator parameter (default True)
- Override support: `compute_posture_score(results, overrides={"CHECK-ID": "PASS"})`
