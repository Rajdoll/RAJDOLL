---
description: Calculate evaluation metrics for research (Precision, Recall, F1-Score)
allowed-tools: Bash, Read, Grep
---

Calculate evaluation metrics for scan: **$1**

**Requirements:**
- Scan must be completed
- Ground truth data must be available (DVWA or Juice Shop)

**Metrics to calculate:**

1. **Effectiveness Metrics:**
   - True Positives (TP): Valid vulnerabilities detected
   - False Positives (FP): False alarms
   - False Negatives (FN): Missed vulnerabilities
   - Precision = TP / (TP + FP)
   - Recall = TP / (TP + FN)
   - F1-Score = 2 × (Precision × Recall) / (Precision + Recall)

2. **Coverage Metrics:**
   - Task Completion Rate (TCR) = Completed tests / Total WSTG tests
   - OWASP Top 10 Coverage = Covered risks / 10

3. **Efficiency Metrics:**
   - Total scan time
   - Time to first finding
   - Average time per test case

**Steps:**
1. Fetch scan results from API
2. Load ground truth for target (DVWA: 25 vulns, Juice Shop: ~100 challenges)
3. Compare findings with ground truth
4. Calculate all metrics
5. Generate comparison table
6. Suggest improvements

**Output format:**
```
📊 Evaluation Results for Scan #$1

🎯 Target: <target_url>
⏱️  Duration: Xh Ym Zs

✅ Effectiveness:
   True Positives:  X
   False Positives: X
   False Negatives: X

   Precision: XX.X%  (Target: ≥90%)
   Recall:    XX.X%  (Target: ≥80%)
   F1-Score:  XX.X%  (Target: ≥85%)

📋 Coverage:
   TCR: XX.X%  (Completed: X/Y WSTG tests)
   OWASP Top 10: X/10 categories covered

⚡ Efficiency:
   Total time: Xh Ym
   Time to first finding: Xm Ys
   Avg time per test: Xm Ys

💡 Recommendations:
   1. <improvement suggestion>
   2. ...
```
