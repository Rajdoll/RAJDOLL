# 📊 Enhanced Evaluation Metrics untuk Agentic AI Penetration Testing System

**Untuk:** Penelitian Martua Raja - NextGCAI
**Tanggal:** 3 Desember 2025

---

## 🎯 Overview

Proposal saat ini sudah memiliki metrik dasar yang bagus:
- ✅ Completion Rate (TCR, SCR, CCR)
- ✅ Technical Testing (ISO/IEC/IEEE 29119)
- ✅ User Acceptance Testing (SUS)

Dokumen ini memberikan **metrik evaluasi tambahan** yang lebih komprehensif untuk penelitian yang lebih robust.

---

## 📐 KATEGORI 1: Accuracy & Effectiveness Metrics

### 1.1 Vulnerability Detection Metrics

#### **Precision (Positive Predictive Value)**
Mengukur seberapa akurat sistem dalam mendeteksi vulnerability yang benar.

```
Precision = True Positives / (True Positives + False Positives) × 100%

Target:
- Minimum: ≥ 85%
- Good: ≥ 90%
- Excellent: ≥ 95%
```

**Cara Mengukur:**
- True Positive (TP): Vulnerability yang benar terdeteksi dan valid
- False Positive (FP): Sistem report vulnerability padahal tidak ada
- Test pada DVWA & Juice Shop (known vulnerabilities)

**Contoh:**
```
DVWA memiliki 25 known vulnerabilities
Sistem detect: 23 vulnerabilities
Valid: 21 vulnerabilities
False positive: 2 vulnerabilities

Precision = 21 / (21 + 2) = 91.3%
```

---

#### **Recall (Sensitivity / True Positive Rate)**
Mengukur seberapa lengkap sistem mendeteksi semua vulnerability yang ada.

```
Recall = True Positives / (True Positives + False Negatives) × 100%

Target:
- Minimum: ≥ 70%
- Good: ≥ 80%
- Excellent: ≥ 90%
```

**Cara Mengukur:**
- False Negative (FN): Vulnerability yang ada tapi tidak terdeteksi

**Contoh:**
```
DVWA memiliki 25 known vulnerabilities
Sistem detect (valid): 21 vulnerabilities
Missed: 4 vulnerabilities

Recall = 21 / (21 + 4) = 84%
```

---

#### **F1-Score (Harmonic Mean of Precision & Recall)**
Metrik balanced yang mengkombinasikan precision dan recall.

```
F1-Score = 2 × (Precision × Recall) / (Precision + Recall)

Target:
- Minimum: ≥ 75%
- Good: ≥ 85%
- Excellent: ≥ 90%
```

**Contoh:**
```
Precision = 91.3%
Recall = 84%

F1-Score = 2 × (0.913 × 0.84) / (0.913 + 0.84) = 87.4%
```

**Keuntungan:**
- Single metric untuk overall performance
- Balanced antara precision dan recall
- Standar dalam security research

---

#### **False Negative Rate (FNR)**
Mengukur seberapa banyak vulnerability yang terlewat.

```
FNR = False Negatives / (False Negatives + True Positives) × 100%

Target: ≤ 20% (semakin rendah semakin baik)
```

**Critical karena:**
- False negative = vulnerability yang tidak terdeteksi
- Lebih berbahaya daripada false positive
- Harus diminimalisir untuk sistem security

---

### 1.2 Severity Classification Accuracy

Mengukur seberapa akurat sistem mengklasifikasikan severity vulnerability.

```
Severity Accuracy = Correctly Classified Severity / Total Findings × 100%

Classification:
- Critical (CVSS 9.0-10.0)
- High (CVSS 7.0-8.9)
- Medium (CVSS 4.0-6.9)
- Low (CVSS 0.1-3.9)
```

**Cara Mengukur:**
```python
# Compare dengan manual expert classification
expert_severity = {
    "vuln_1": "critical",
    "vuln_2": "high",
    "vuln_3": "medium"
}

system_severity = {
    "vuln_1": "critical",  # ✓ Correct
    "vuln_2": "critical",  # ✗ Overestimated
    "vuln_3": "medium"     # ✓ Correct
}

Accuracy = 2/3 = 66.7%
```

**Target: ≥ 80%**

---

### 1.3 CVSS Score Correlation

Mengukur korelasi antara CVSS score yang diberikan sistem vs expert assessment.

```
Correlation Coefficient (Pearson's r)

r = Σ[(xi - x̄)(yi - ȳ)] / √[Σ(xi - x̄)² × Σ(yi - ȳ)²]

Target:
- Minimum: r ≥ 0.7 (strong correlation)
- Good: r ≥ 0.8 (very strong)
- Excellent: r ≥ 0.9 (nearly perfect)
```

**Interpretation:**
- r = 1.0: Perfect positive correlation
- r = 0.7-0.9: Strong correlation
- r < 0.7: Needs improvement

---

## 📐 KATEGORI 2: Efficiency & Performance Metrics

### 2.1 Time Efficiency Metrics

#### **Scan Time per Test Case**

```
Average Scan Time = Total Scan Duration / Number of Test Cases

Benchmark:
- Manual pentest: ~30-60 min per test case
- Automated scanner (ZAP): ~10-15 min per test case

Target:
- System should be ≤ 10 min per test case
- 50-80% faster than manual testing
```

**Breakdown by Category:**
```
Information Gathering: ≤ 5 min
Configuration Testing: ≤ 8 min
Authentication Testing: ≤ 12 min
Input Validation: ≤ 15 min (most time-consuming)
Session Management: ≤ 10 min
Error Handling: ≤ 5 min
Cryptography: ≤ 8 min
Business Logic: ≤ 12 min
Client-Side: ≤ 5 min
```

---

#### **Time to First Finding (TTFF)**

Mengukur seberapa cepat sistem menemukan vulnerability pertama.

```
TTFF = Timestamp(First Finding) - Timestamp(Scan Start)

Target: ≤ 5 minutes

Benchmark:
- Excellent: < 3 minutes
- Good: 3-5 minutes
- Acceptable: 5-10 minutes
```

**Importance:**
- Quick feedback untuk pengguna
- Indikator efisiensi reconnaissance phase
- Critical untuk CI/CD integration

---

#### **Scan Completion Time**

Total waktu untuk menyelesaikan semua test cases.

```
Total Scan Time = Timestamp(End) - Timestamp(Start)

Target:
- Full WSTG scan (11 categories): ≤ 4 hours
- Baseline comparison: Manual pentest = 8-16 hours

Speedup Factor = Manual Time / System Time
Target Speedup: ≥ 2x (minimal 50% lebih cepat)
```

**Example:**
```
Manual pentest: 12 hours
System scan: 3.5 hours
Speedup: 12 / 3.5 = 3.4x (240% faster)
```

---

### 2.2 Resource Utilization Metrics

#### **CPU Utilization**

```
Average CPU Usage = Σ(CPU% per second) / Total Seconds

Target:
- Average: ≤ 70%
- Peak: ≤ 90%
- Idle periods: ≤ 10%
```

**Measurement:**
```python
import psutil
import time

def measure_cpu():
    readings = []
    for _ in range(60):  # 1 minute sampling
        cpu = psutil.cpu_percent(interval=1)
        readings.append(cpu)

    return {
        "average": sum(readings) / len(readings),
        "peak": max(readings),
        "min": min(readings)
    }
```

---

#### **Memory Utilization**

```
Memory Efficiency = Peak Memory Usage / Available RAM × 100%

Target:
- Peak memory: ≤ 4 GB
- Average: ≤ 2 GB
- No memory leaks (stable over time)
```

**Memory Leak Detection:**
```python
import tracemalloc

tracemalloc.start()

# Run scan
scan_start_memory = tracemalloc.get_traced_memory()
run_full_scan()
scan_end_memory = tracemalloc.get_traced_memory()

memory_growth = scan_end_memory[0] - scan_start_memory[0]

# Should be minimal after garbage collection
gc.collect()
final_memory = tracemalloc.get_traced_memory()

# Memory leak indicator
if final_memory[0] > scan_start_memory[0] * 1.1:  # >10% increase
    print("⚠️ Potential memory leak detected")
```

---

#### **Network Bandwidth Usage**

```
Bandwidth Efficiency = Total Data Transferred / Scan Duration

Target:
- Average: ≤ 10 Mbps
- Peak: ≤ 50 Mbps
- Respectful to target server (no DoS)
```

**Importance:**
- Prevents overwhelming target systems
- Compliance with ethical hacking guidelines
- Reduces detection by IDS/IPS

---

### 2.3 Scalability Metrics

#### **Concurrent Scan Capability**

Mengukur berapa banyak target yang bisa di-scan secara bersamaan.

```
Max Concurrent Scans = Number of parallel scans without degradation

Target:
- Minimum: 3 concurrent scans
- Good: 5 concurrent scans
- Excellent: 10+ concurrent scans

Performance Degradation Threshold: ≤ 20%
```

**Test:**
```
Scan 1 target: 60 minutes
Scan 3 targets (parallel): 75 minutes (vs 180 if sequential)

Efficiency = (3 × 60) / 75 = 2.4x speedup
Degradation = (75 - 60) / 60 = 25% (Acceptable if < 20% target)
```

---

#### **Agent Throughput**

Mengukur berapa banyak test cases yang bisa diselesaikan per jam.

```
Agent Throughput = Test Cases Completed / Hour

Benchmark:
- Single agent: ~4-6 test cases/hour
- Multi-agent system: ~15-25 test cases/hour

Target: ≥ 20 test cases/hour
```

---

## 📐 KATEGORI 3: Intelligence & Automation Metrics

### 3.1 LLM Reasoning Quality

#### **Reasoning Accuracy**

Mengukur seberapa akurat LLM dalam reasoning untuk vulnerability analysis.

```
Reasoning Accuracy = Correct Reasoning Steps / Total Reasoning Steps × 100%

Evaluation:
- Manual review by security experts
- Compare reasoning trace dengan standard methodology

Target: ≥ 85%
```

**Example Evaluation:**
```
LLM Reasoning Trace:
1. ✓ Identified SQL injection point (correct)
2. ✓ Selected appropriate payload (correct)
3. ✗ Misinterpreted error message (incorrect)
4. ✓ Confirmed vulnerability (correct)

Accuracy = 3/4 = 75%
```

---

#### **Hallucination Rate**

Mengukur seberapa sering LLM "mengarang" findings yang tidak ada.

```
Hallucination Rate = Hallucinated Findings / Total Findings × 100%

Target: ≤ 5% (semakin rendah semakin baik)

Hallucination Types:
- Non-existent vulnerabilities
- Incorrect CVSS scores
- Wrong remediation advice
- Fabricated CVE references
```

**Detection Method:**
```python
def detect_hallucination(finding):
    # Check 1: CVE exists?
    if finding.cve and not verify_cve_exists(finding.cve):
        return True, "CVE hallucination"

    # Check 2: Evidence valid?
    if not validate_evidence(finding.evidence):
        return True, "Evidence hallucination"

    # Check 3: Vulnerability reproducible?
    if not reproduce_vulnerability(finding):
        return True, "Non-reproducible"

    return False, None
```

---

#### **Context Retention**

Mengukur seberapa baik sistem mempertahankan context antar agent.

```
Context Retention Rate = Successful Context Transfers / Total Transfers × 100%

Target: ≥ 95%

Measurement:
- Track context loss events
- Measure context restoration success
- Monitor shared state consistency
```

**Test Scenario:**
```
1. Recon agent finds 10 subdomains
2. Pass to Config agent
3. Config agent should receive all 10

If only 9 received: Context loss event
```

---

### 3.2 Automation Level

#### **Human Intervention Rate**

Mengukur seberapa sering manusia perlu intervensi.

```
Intervention Rate = Manual Interventions / Total Test Cases × 100%

Target: ≤ 10% (90% autonomous)

Benchmark:
- Fully manual: 100%
- Semi-automated (ZAP): ~30-40%
- Highly automated: <10%
```

**Intervention Types:**
```
- Confirmation requests: Counted
- Error recovery: Counted
- Result interpretation: Counted
- Report customization: Not counted (expected)
```

---

#### **Self-Correction Success Rate**

Mengukur seberapa sering sistem berhasil self-correct tanpa intervensi.

```
Self-Correction Rate = Successful Auto-Corrections / Total Errors × 100%

Target: ≥ 70%

Examples:
- Auto-retry after timeout: Success
- Context restoration: Success
- Tool fallback: Success
- Graceful degradation: Success
```

---

### 3.3 Adaptive Learning Metrics

#### **Improvement Over Time**

Mengukur apakah sistem "belajar" dari pengalaman (jika ada ML component).

```
Learning Rate = (Performance_Week_N - Performance_Week_1) / Performance_Week_1 × 100%

Tracked Metrics:
- False positive reduction over time
- Scan time optimization
- Tool selection improvement
```

**Note:** Ini opsional jika ada ML/fine-tuning component.

---

## 📐 KATEGORI 4: Coverage & Completeness Metrics

### 4.1 WSTG Coverage Metrics (Sudah ada, tapi diperluas)

#### **Test Case Coverage (TCR)** - Sudah ada ✓

```
TCR = Completed Test Cases / Total WSTG Test Cases × 100%

Enhanced breakdown:
- Category-level coverage (11 categories)
- Sub-category coverage (per WSTG ID)
- Critical path coverage (prioritized tests)
```

---

#### **OWASP Top 10 Coverage**

Tambahan selain WSTG: mapping ke OWASP Top 10 2021.

```
OWASP Top 10 Coverage = Covered Risks / 10 × 100%

OWASP Top 10 2021:
1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Authentication Failures
8. Software & Data Integrity Failures
9. Security Logging & Monitoring Failures
10. SSRF

Target: ≥ 8/10 = 80%
```

**Mapping Table:**
```
WSTG Category → OWASP Top 10 2021

WSTG-ATHN → #7 Authentication Failures
WSTG-ATHZ → #1 Broken Access Control
WSTG-INPV-05 (SQLi) → #3 Injection
WSTG-INPV-01 (XSS) → #3 Injection
WSTG-SESS → #1 Broken Access Control
WSTG-CRYP → #2 Cryptographic Failures
WSTG-CONF → #5 Security Misconfiguration
WSTG-INPV-19 (SSRF) → #10 SSRF
...
```

---

#### **Attack Surface Coverage**

Mengukur seberapa lengkap sistem meng-cover attack surface.

```
Attack Surface Coverage = Tested Entry Points / Total Entry Points × 100%

Entry Point Types:
- URL endpoints
- Form inputs
- API endpoints
- File uploads
- Headers
- Cookies

Target: ≥ 90%
```

**Measurement:**
```python
total_endpoints = reconnaissance_data["total_endpoints"]  # e.g., 50
tested_endpoints = len(set(finding.location for finding in findings))  # e.g., 46

coverage = tested_endpoints / total_endpoints * 100  # 92%
```

---

### 4.2 Depth of Testing

#### **Exploitation Depth**

Mengukur seberapa dalam sistem bisa mengeksploitasi vulnerability.

```
Exploitation Levels:
1. Detection only (vulnerability exists)
2. Basic exploitation (proof of concept)
3. Advanced exploitation (data extraction)
4. Post-exploitation (privilege escalation)

Depth Score = Average Exploitation Level across findings

Target: ≥ 2.5 (between PoC and data extraction)
```

**Example:**
```
Finding 1 (SQLi): Level 3 (extracted database names)
Finding 2 (XSS): Level 2 (PoC alert box)
Finding 3 (Auth bypass): Level 4 (gained admin access)

Average = (3 + 2 + 4) / 3 = 3.0
```

---

#### **Chained Attack Detection**

Mengukur kemampuan mendeteksi multi-step attack chains.

```
Chain Detection Rate = Detected Chains / Total Possible Chains × 100%

Example Chains:
- Auth bypass → Session hijacking → Data exfiltration
- XSS → Cookie theft → Account takeover
- SSRF → Internal network access → Privilege escalation

Target: ≥ 60%
```

---

## 📐 KATEGORI 5: Reliability & Stability Metrics

### 5.1 System Reliability

#### **Mean Time Between Failures (MTBF)**

```
MTBF = Total Operating Time / Number of Failures

Target: ≥ 100 hours

Benchmark:
- Poor: < 10 hours
- Acceptable: 10-50 hours
- Good: 50-100 hours
- Excellent: > 100 hours
```

---

#### **Crash Rate**

```
Crash Rate = System Crashes / Total Scans × 100%

Target: ≤ 2%

Severity:
- Critical crash: Complete system failure
- Partial crash: Single agent failure (recoverable)
```

---

#### **Recovery Success Rate**

```
Recovery Rate = Successful Recoveries / Total Failures × 100%

Target: ≥ 90%

Recovery Mechanisms:
- Auto-restart failed agents
- Context restoration
- State rollback
- Graceful degradation
```

---

### 5.2 Consistency & Reproducibility

#### **Scan Consistency**

Mengukur apakah scan yang sama menghasilkan hasil yang konsisten.

```
Consistency Test:
- Run same scan 3 times
- Compare results

Consistency Score = Identical Findings / Total Findings × 100%

Target: ≥ 95% (minor variations acceptable)
```

**Acceptable Variations:**
- Timing differences
- Non-deterministic LLM responses (minor wording changes)
- Network latency effects

**Unacceptable Variations:**
- Different vulnerabilities found
- Different severity classifications
- Missing critical findings

---

## 📐 KATEGORI 6: Usability & User Experience (Sudah ada SUS, ditambah)

### 6.1 Task Success Rate (TSR)

```
TSR = Successful Task Completions / Total Task Attempts × 100%

User Tasks:
1. Initiate scan on target URL
2. Monitor scan progress
3. View findings
4. Export report
5. Understand remediation steps

Target: ≥ 90%
```

---

### 6.2 Time on Task (ToT)

```
ToT = Average time users take to complete tasks

Benchmark Tasks:
- Setup new scan: ≤ 2 minutes
- Review findings: ≤ 5 minutes
- Generate report: ≤ 1 minute

Comparison:
- Manual pentest report: 2-4 hours
- System report: < 5 minutes
```

---

### 6.3 Error Rate (User Errors)

```
User Error Rate = User Mistakes / Total Actions × 100%

Target: ≤ 5%

Common Errors:
- Incorrect URL format
- Missing authorization
- Misunderstanding findings
```

---

## 📐 KATEGORI 7: Cost & ROI Metrics (Bonus untuk Industri)

### 7.1 Cost per Scan

```
Cost per Scan = (LLM API Cost + Infrastructure Cost) / Number of Scans

Target: ≤ $5 per full scan

Breakdown:
- LLM API calls (Claude/GPT): ~$2-3
- Infrastructure (compute): ~$1-2
- Storage & bandwidth: ~$0.50

Total: ~$3.50-5.50 per scan
```

**ROI Calculation:**
```
Manual Pentest Cost: $5,000 - $15,000 (konsultan eksternal)
System Cost: $5 per scan
Annual license: $1,000

ROI = (Manual Cost - System Cost) / System Cost × 100%
ROI = ($10,000 - $1,000) / $1,000 = 900% (9x return)
```

---

### 7.2 LLM Token Efficiency

```
Token Efficiency = Findings Generated / Total Tokens Used

Target: ≥ 0.001 findings per token

Optimization:
- Minimize prompt length
- Cache repetitive contexts
- Use smaller models for simple tasks
```

---

## 📊 RECOMMENDED METRIC DASHBOARD

### Priority 1: Must Have (Core Metrics)

```yaml
Effectiveness:
  - F1-Score: ≥ 85%
  - False Positive Rate: ≤ 15%
  - WSTG Coverage (TCR): ≥ 70%

Efficiency:
  - Total Scan Time: ≤ 4 hours
  - Time to First Finding: ≤ 5 minutes
  - Speedup vs Manual: ≥ 2x

Usability:
  - SUS Score: ≥ 68
  - Task Success Rate: ≥ 90%

Reliability:
  - Crash Rate: ≤ 2%
  - Recovery Rate: ≥ 90%
```

---

### Priority 2: Should Have (Enhanced Metrics)

```yaml
Advanced Effectiveness:
  - Recall: ≥ 80%
  - Precision: ≥ 90%
  - Severity Classification Accuracy: ≥ 80%

Intelligence:
  - Hallucination Rate: ≤ 5%
  - Reasoning Accuracy: ≥ 85%
  - Context Retention: ≥ 95%

Coverage:
  - OWASP Top 10 Coverage: ≥ 80%
  - Attack Surface Coverage: ≥ 90%
```

---

### Priority 3: Nice to Have (Advanced Metrics)

```yaml
Performance:
  - CPU Utilization: ≤ 70%
  - Memory Efficiency: ≤ 4GB peak
  - Concurrent Scan Capability: ≥ 5

Depth:
  - Exploitation Depth Score: ≥ 2.5
  - Chained Attack Detection: ≥ 60%

Cost:
  - Cost per Scan: ≤ $5
  - Token Efficiency: ≥ 0.001
```

---

## 📏 COMPARISON TABLE: Metrik Proposal vs Enhanced

| Aspek | Proposal Saat Ini | Enhanced Metrics |
|-------|------------------|------------------|
| **Effectiveness** | ✓ Completion Rate | ✓ + Precision, Recall, F1-Score, FNR |
| **Efficiency** | ✗ Tidak spesifik | ✓ Scan time, TTFF, Speedup, Throughput |
| **Accuracy** | ✗ Implisit via testing | ✓ Explicit: FPR, Severity accuracy, CVSS correlation |
| **Coverage** | ✓ TCR, SCR, CCR | ✓ + OWASP Top 10, Attack surface, Depth |
| **Reliability** | ✗ Tidak ada | ✓ MTBF, Crash rate, Recovery rate, Consistency |
| **Intelligence** | ✗ Tidak ada | ✓ Hallucination, Reasoning, Context retention |
| **Usability** | ✓ SUS | ✓ + TSR, ToT, Error rate |
| **Resource** | ✗ Via performance testing | ✓ Explicit: CPU, Memory, Bandwidth |
| **Cost** | ✗ Tidak ada | ✓ Cost per scan, ROI, Token efficiency |
| **Automation** | ✗ Tidak ada | ✓ Intervention rate, Self-correction rate |

---

## 🎯 RECOMMENDED ADDITIONS TO PROPOSAL

### Tambahkan ke Bab 5 (Metode Pengujian dan Evaluasi):

```markdown
## 5. Metode Pengujian dan Evaluasi (ENHANCED)

Evaluasi sistem dilakukan melalui EMPAT komponen utama:

### a. Effectiveness Metrics (BARU)

**1. Precision & Recall**
- Precision: Mengukur akurasi deteksi (target ≥ 90%)
- Recall: Mengukur kelengkapan deteksi (target ≥ 80%)
- F1-Score: Balanced metric (target ≥ 85%)

Formula:
```
Precision = TP / (TP + FP) × 100%
Recall = TP / (TP + FN) × 100%
F1-Score = 2 × (Precision × Recall) / (Precision + Recall)
```

Pengukuran menggunakan DVWA & OWASP Juice Shop sebagai ground truth.

**2. False Positive Rate (FPR)**
- Target: ≤ 15%
- Diukur dengan membandingkan findings sistem vs manual expert validation

**3. Severity Classification Accuracy**
- Mengukur ketepatan klasifikasi severity (Critical/High/Medium/Low)
- Target: ≥ 80% agreement dengan expert assessment

### b. Efficiency Metrics (BARU)

**1. Time to First Finding (TTFF)**
- Mengukur kecepatan sistem menemukan vulnerability pertama
- Target: ≤ 5 menit

**2. Total Scan Time**
- Full WSTG scan completion time
- Target: ≤ 4 jam
- Baseline: Manual pentest = 8-16 jam
- Expected speedup: ≥ 2x

**3. Agent Throughput**
- Test cases completed per hour
- Target: ≥ 20 test cases/hour

### c. Completion Rate (EXISTING - KEEP)
[Tetap seperti proposal asli: TCR, SCR, CCR]

### d. Technical Testing (EXISTING - KEEP)
[Tetap seperti proposal asli: Unit, Integration, System, Performance]

### e. Intelligence Metrics (BARU)

**1. LLM Hallucination Rate**
- Mengukur seberapa sering LLM "mengarang" findings
- Target: ≤ 5%
- Validasi: Manual verification & CVE cross-check

**2. Context Retention Rate**
- Mengukur konsistensi shared state antar agent
- Target: ≥ 95%

**3. Self-Correction Success Rate**
- Mengukur autonomous error recovery
- Target: ≥ 70%

### f. Coverage Metrics (ENHANCED)

**1. WSTG Coverage (EXISTING)**
[Tetap seperti proposal asli]

**2. OWASP Top 10 2021 Coverage (BARU)**
- Mapping findings ke OWASP Top 10 risks
- Target: ≥ 8/10 categories (80%)

**3. Attack Surface Coverage (BARU)**
- Persentase entry points yang di-test
- Target: ≥ 90%

### g. Reliability Metrics (BARU)

**1. System Stability**
- Crash Rate: ≤ 2%
- Recovery Success Rate: ≥ 90%
- Mean Time Between Failures (MTBF): ≥ 100 hours

**2. Scan Consistency**
- Reproducibility: ≥ 95% (same scan, same results)

### h. User Acceptance Testing - SUS (EXISTING - KEEP)
[Tetap seperti proposal asli]
```

---

## 📊 SUMMARY TABLE: All Metrics

| # | Metric | Category | Target | Priority |
|---|--------|----------|--------|----------|
| 1 | F1-Score | Effectiveness | ≥ 85% | Must Have |
| 2 | Precision | Effectiveness | ≥ 90% | Must Have |
| 3 | Recall | Effectiveness | ≥ 80% | Must Have |
| 4 | False Positive Rate | Effectiveness | ≤ 15% | Must Have |
| 5 | WSTG Coverage (TCR) | Coverage | ≥ 70% | Must Have |
| 6 | Scan Time | Efficiency | ≤ 4 hrs | Must Have |
| 7 | Time to First Finding | Efficiency | ≤ 5 min | Should Have |
| 8 | Speedup vs Manual | Efficiency | ≥ 2x | Must Have |
| 9 | SUS Score | Usability | ≥ 68 | Must Have |
| 10 | Task Success Rate | Usability | ≥ 90% | Should Have |
| 11 | Crash Rate | Reliability | ≤ 2% | Must Have |
| 12 | Recovery Rate | Reliability | ≥ 90% | Must Have |
| 13 | Hallucination Rate | Intelligence | ≤ 5% | Should Have |
| 14 | Context Retention | Intelligence | ≥ 95% | Should Have |
| 15 | Severity Accuracy | Effectiveness | ≥ 80% | Should Have |
| 16 | OWASP Top 10 Coverage | Coverage | ≥ 80% | Should Have |
| 17 | Attack Surface Coverage | Coverage | ≥ 90% | Should Have |
| 18 | Agent Throughput | Efficiency | ≥ 20/hr | Nice to Have |
| 19 | CPU Utilization | Performance | ≤ 70% | Nice to Have |
| 20 | Memory Peak | Performance | ≤ 4GB | Nice to Have |
| 21 | Concurrent Scans | Scalability | ≥ 5 | Nice to Have |
| 22 | Exploitation Depth | Coverage | ≥ 2.5 | Nice to Have |
| 23 | Cost per Scan | Cost | ≤ $5 | Nice to Have |
| 24 | Self-Correction Rate | Intelligence | ≥ 70% | Nice to Have |
| 25 | Scan Consistency | Reliability | ≥ 95% | Should Have |

---

## ✅ RECOMMENDED METRICS FOR PROPOSAL

Saya sarankan **tambahkan 10 metrik ini** ke proposal (selain yang sudah ada):

### High Priority (Must Add):
1. ✅ **Precision** (≥ 90%) - Akurasi deteksi
2. ✅ **Recall** (≥ 80%) - Kelengkapan deteksi
3. ✅ **F1-Score** (≥ 85%) - Balanced metric
4. ✅ **False Positive Rate** (≤ 15%) - Menggantikan yang sudah ada di proposal
5. ✅ **Time to First Finding** (≤ 5 min) - Kecepatan
6. ✅ **Total Scan Time** (≤ 4 hours) - Efisiensi keseluruhan

### Medium Priority (Should Add):
7. ✅ **Hallucination Rate** (≤ 5%) - LLM quality
8. ✅ **OWASP Top 10 Coverage** (≥ 80%) - Broader coverage
9. ✅ **Crash Rate** (≤ 2%) - Reliability
10. ✅ **Recovery Success Rate** (≥ 90%) - Resilience

---

## 📖 REFERENSI TAMBAHAN

```
1. Doup� et al. (2010). "Why Johnny Can't Pentest: An Analysis of
   Black-Box Web Vulnerability Scanners". DIMVA 2010.
   → Standard untuk evaluasi scanner effectiveness

2. Bau et al. (2010). "A Quantitative Study of Accuracy in System
   Call-Based Malware Detection". ISSTA 2010.
   → Precision/Recall metrics untuk security systems

3. Vieira et al. (2009). "Benchmarking Vulnerability Detection Tools
   for Web Services". IEEE ICWS.
   → Benchmark methodology untuk vuln scanners

4. Antunes & Vieira (2015). "Defending Against Web Application
   Vulnerabilities". IEEE Computer Society.
   → Effectiveness metrics untuk web security

5. Li et al. (2022). "LLM for Security: Opportunities and Challenges"
   → Hallucination metrics untuk LLM-based security tools
```

---

**End of Document**
