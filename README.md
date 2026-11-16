# CyberMate — Defensive Cybersecurity Threat Detection & Diagnosis Expert System

> "A practical cybersecurity reasoning assistant powered by a deterministic expert rule engine."

CyberMate is a defensive cybersecurity threat detection and diagnosis web application. Built for security analysts, incident responders, and systems engineers, CyberMate applies deterministic expert-system logic, declarative rule sets, transparent evidence tracing, and an empirical risk scoring algorithm to analyze suspicious security telemetry, identify probable threats, and prescribe concrete defensive mitigations.

**Important:** CyberMate is strictly a defensive intelligence tool. It contains **zero** offensive exploitation, payload generation, credential harvesting, or bypass capabilities.

---

## 1. Key Features

- **Deterministic Expert Inference Engine**: Evaluates observed indicators using declarative forward-chaining rules. Explains exactly *why* a threat was classified with bulleted evidence.
- **Comprehensive 49-Rule Defensive Catalog**: Spans 7 critical security domains:
  - Authentication & Access Control (Brute Force, Credential Stuffing, Account Takeover, MFA Fatigue, Impossible Travel, Dormant Accounts)
  - Network & Perimeter (DNS Tunneling, Volumetric Exfiltration, C2 Beaconing, Port Scans, Tor/Proxy Traffic, DoS)
  - System & Endpoint (Ransomware, Living-off-the-Land Binaries, Antivirus Disablement, Registry & Scheduled Task Persistence, Shadow Copy Deletion)
  - Application & Web (SQL Injection, Cross-Site Scripting, Remote Code Execution, Path Traversal, SSRF, API BOLA)
  - Email & Social Engineering (Spearphishing, Malicious Macro Attachments, Business Email Compromise, Inbox Auto-Forwarding Rules)
  - Cloud Infrastructure (IAM Role Assumption Anomalies, Public S3 Storage Exposure, Cryptomining Clusters, Vault Secret Downloads)
  - Insider & Operational Risk (Mass File Deletion, Departing Employee Downloads, Removable USB Exfiltration, Security Log Tampering)
- **Dual Incident Analysis Methods**:
  - **Method A — Structured Observation Form**: Grouped indicators by domain with real-time risk previews and custom value inputs.
  - **Method B — Conversational Assistant**: Natural language intake extracting structured facts and feeding them into the deterministic rule engine.
- **CyberMate Risk Scoring Engine**: Calculates transparent 0–100 risk scores with category breakdown bars and prioritized containment actions.
- **Interactive Simulated Scenarios**: Safe educational test cases (Ransomware, Account Takeover, DNS Exfiltration, Phishing) to test expert-system inference on simulated telemetry logs.
- **Searchable Defensive Threat Library**: Detailed profiles with MITRE ATT&CK techniques, common indicators, and defensive remediation strategies.
- **NIST SP 800-63B Password Generator**: Cryptographically secure client/server CSPRNG with entropy analysis and a strict zero-storage guarantee.
- **Local SQLite Audit History**: Chronological incident records, expandable report modal, and clear history with confirmation.
- **Refined Minimalist UI**: Dark mode default + crafted light mode, subtle borders, responsive on desktop/tablet/mobile, zero AI-slop visual noise.

---

## 2. Technology Stack

### Frontend
- **Framework**: React 19 + TypeScript + Vite
- **Styling**: Tailwind CSS (custom dark/light cybersecurity color system)
- **Icons**: Lucide Icons
- **Theme**: LocalStorage persisted Dark/Light mode with CSS transitions

### Backend
- **Framework**: Python 3.12+ / 3.14 + FastAPI
- **Inference Engine**: Deterministic Python Expert System (`app.rules.engine`)
- **Database**: SQLite with SQLAlchemy ORM (architected for instant PostgreSQL migration)
- **Validation**: Pydantic v2 schemas
- **Testing**: Pytest

---

## 3. How the Expert System Works

CyberMate strictly separates **fact extraction** from **decision inference**:

```text
Observations (UI Form / Natural Language Input)
      ↓
Fact Normalization (e.g. failed_login_count: 20, login_from_unknown_ip: true)
      ↓
Rule Matching (Evaluates 49 declarative cybersecurity rules)
      ↓
Inference & Multi-Threat Ranking (Primary threat + related threats by evidence)
      ↓
Transparent Explanation (Shows matched indicators & MITRE ATT&CK techniques)
      ↓
Risk Score (0–100 scale: Low, Moderate, High, Critical)
      ↓
Prescriptive Defensive Mitigations (Prioritized operational roadmap)
```

### Transparent Rule Definition Example
```python
Rule(
    id="AUTH-002",
    name="Successful Authentication After Multiple Failures",
    category="Authentication",
    threat="Account Takeover",
    severity="CRITICAL",
    base_confidence=0.92,
    mitre_technique="T1110 - Brute Force / Account Access",
    conditions=[
        Condition(field="failed_login_count", operator="gte", value=5),
        Condition(field="successful_login_after_failures", operator="is_true")
    ],
    explanation_template="Repeated failed logins followed by successful authentication indicates cracked credentials.",
    recommendations=[
        "Immediately revoke active sessions and refresh tokens.",
        "Force out-of-band credential reset.",
        "Audit recent session activities."
    ]
)
```

---

## 4. How to Run

### Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 1. Running the Backend
From the root directory:
```bash
cd backend
python run.py
```
The FastAPI backend server will start at: `http://127.0.0.1:8000`  
Swagger API Documentation is available at: `http://127.0.0.1:8000/docs`

### 2. Running the Frontend
In a separate terminal:
```bash
cd frontend
npm run dev
```
Open your browser to: `http://localhost:5173`

The Vite dev server proxies API calls (`/api`) directly to `http://127.0.0.1:8000`.

---

## 5. Running Automated Tests

To run the complete suite of 20 unit and integration tests:
```bash
cd backend
python -m pytest tests -v
```

Test coverage includes:
- Brute Force & Account Takeover detection
- Ransomware & Cryptomining process anomalies
- Phishing & Attachment malware indicators
- No-threat edge case (empty inputs)
- Multiple simultaneous threat ranking (CRITICAL over HIGH)
- Deterministic consistency across repeated runs
- Low-confidence partial-match handling
- Rule catalog structural integrity (49 active rules)
- Full API endpoint operations

---

## 6. Environment Variables

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite:///./cybermate.db` | SQLAlchemy connection string. Set to `postgresql://user:pass@host/db` for Postgres. |
| `GEMINI_API_KEY` | *(Optional)* | Optional future hook for enhanced natural language interpretation. Rule classification remains 100% deterministic without any key. |
| `PORT` | `8000` | Backend port |

---

## 7. Architecture & Future Roadmap

1. **Authentication**: Architecture is decoupled to add OAuth2 / OIDC (Okta, Entra ID) without touching rule logic.
2. **PostgreSQL Migration**: Zero code changes required; simply provide `DATABASE_URL=postgresql://...`.
3. **SIEM Connectors**: Webhook ingestion for Splunk, Elastic, and Microsoft Sentinel CEF/LEEF event streams.
4. **Dynamic Rule Packs**: Support for hot-loading Sigma and YARA defensive rules.
