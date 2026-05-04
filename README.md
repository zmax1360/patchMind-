# PatchMind 🛡️

> **AI-powered multi-agent security vulnerability remediation platform**  
> From Dependabot alert to audit-ready PR — in minutes, not days.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)](https://python.org)
[![CrewAI](https://img.shields.io/badge/CrewAI-0.80+-orange?style=flat-square)](https://crewai.com)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-green?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Claude](https://img.shields.io/badge/Claude-Sonnet_4-purple?style=flat-square)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-gray?style=flat-square)](LICENSE)

---

## What Is PatchMind?

PatchMind is a **multi-agent AI system** that automates the full security remediation lifecycle:

1. **Ingests** real Dependabot alerts from any GitHub repository
2. **Analyzes** vulnerabilities against the NVD database
3. **Fixes** the actual code in a cloned repository
4. **Verifies** the fix with real test execution
5. **Documents** an audit-ready PR with compliance references
6. **Waits** for human approval before pushing anything

> Built for financial services teams drowning in remediation backlogs.  
> Works on any GitHub instance including GitHub Enterprise.

---

## Live Demo

```
50 open alerts → select CVE-2025-6545 (pbkdf2 CRITICAL)
→ 4 agents fire sequentially
→ package.json patched, overrides added
→ Gate 3 verifies version exists on npm registry
→ Confidence score: 90/100
→ Human approves → PR created on GitHub
→ Audit trail: PATCHMIND-0161
Total time: ~4 minutes
```

---

## Architecture

### Agent Pipeline

```
GitHub Dependabot Alert
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│                    PATCHMIND PIPELINE                        │
│                                                             │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌───────┐ │
│  │  PRIYA   │───▶│  MARCUS  │───▶│   DANA   │───▶│ JAMES │ │
│  │Analyst   │    │  Fixer   │    │Verifier  │    │  PR   │ │
│  │          │    │          │    │          │    │Writer │ │
│  │• NVD CVE │    │• Read    │    │• Run     │    │• Diff │ │
│  │  lookup  │    │  package │    │  tests   │    │• OSFI │ │
│  │• Read    │    │• Apply   │    │• Score   │    │• PCI  │ │
│  │  repo    │    │  fix     │    │  fix     │    │• FFIEC│ │
│  │• Map     │    │• Verify  │    │• Report  │    │• Audit│ │
│  │  paths   │    │  diff    │    │  risk    │    │  trail│ │
│  └──────────┘    └──────────┘    └──────────┘    └───────┘ │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
    5 Guardrail Gates
         │
         ▼
    Human Approval
         │
         ▼
    PR on GitHub
```

---

## Guardrails Architecture

The most important part of PatchMind. **No fix reaches a branch without passing 5 explicit gates.**

```
                    ┌─────────────────────────────────────────┐
                    │         GUARDRAIL PIPELINE               │
                    └─────────────────────────────────────────┘

Alert ──▶ GATE 1 ──▶ GATE 2 ──▶ GATE 3 ──▶ GATE 4 ──▶ GATE 5 ──▶ PR
          │           │           │           │           │
          ▼           ▼           ▼           ▼           ▼
       VALIDATE    VALIDATE    VALIDATE    VALIDATE    HUMAN
        ALERT      ANALYSIS      FIX       VERIFY     APPROVAL
          │           │           │           │           │
    ┌─────┴────┐ ┌────┴────┐ ┌───┴────┐ ┌───┴────┐ ┌───┴────┐
    │ • Has    │ │ • Pack- │ │ • Diff │ │ • Con- │ │ • Must │
    │   package│ │   age   │ │   not  │ │   fid- │ │   be   │
    │ • Has    │ │   name  │ │   empty│ │   ence │ │   patchm│
    │   patched│ │   found │ │ • Ver- │ │   ≥ 70 │ │   ind/ │
    │   version│ │ • CVE   │ │   sion │ │ • Tests│ │   branch│
    │ • Valid  │ │   refer-│ │   in   │ │   pass │ │ • Only │
    │   CVE/   │ │   enced │ │   file │ │   or   │ │   pkg  │
    │   GHSA   │ │ • Output│ │ • VER- │ │   human│ │   files│
    │          │ │   > 200 │ │   SION │ │   gate │ │ • Human│
    │          │ │   chars │ │   EX-  │ │        │ │   must │
    │          │ │         │ │   ISTS │ │        │ │   click│
    │          │ │         │ │   ON   │ │        │ │   APPR-│
    │          │ │         │ │   npm* │ │        │ │   OVE  │
    └──────────┘ └─────────┘ └────────┘ └────────┘ └────────┘

    * Gate 3 makes a REAL API call to registry.npmjs.org
      to verify the version exists before allowing the fix.
      The AI cannot hallucinate a version number.

Gate Results:
  ✅ pass           → continue to next gate
  ⚠️  warn          → continue with flag
  🔵 human_required → pause, notify human, wait for approval
  🔴 block          → pipeline stops, reason logged
```

### Why Guardrails Matter

| Scenario | Without Guardrails | With PatchMind |
|---|---|---|
| AI invents version `>=99.0.0` | Fix merged, build breaks | Gate 3 blocks — version doesn't exist on registry |
| Analyst produces empty output | Fixer works on nothing | Gate 2 retries, blocks if still empty |
| Tests fail after fix | Fix merged, app broken | Gate 4 flags human review |
| Agent modifies source files | Unexpected code changes | Gate 5 blocks — only package files allowed |
| Push to main directly | Disaster | Gate 5 always requires human approval |

---

## Multi-Agent Design

### Why Not a Single Agent?

A single agent that fixes and verifies its own work is like a developer who writes code and approves their own PR.

**Multi-agent means the verifier is adversarial by design.** Dana's entire job is to break Marcus's fix. That separation is the only way a bank's risk team will sign off on automated remediation.

```
Single Agent:          Multi-Agent (PatchMind):
                       
"Fix this vuln"        Priya  → what is it really?
      │                Marcus → apply minimal fix
      ▼                Dana   → try to break it
"Here's a fix"         James  → document for regulators
      │
  Trust me?            Each agent has different tools,
                       different goals, different incentives.
```

In functional programming terms: each agent is a pure transformation with clear inputs and outputs. The pipeline is composable. You can swap out the fixer without touching the verifier.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Agent orchestration | CrewAI 0.80+ |
| LLM | Claude Sonnet 4 (Anthropic) |
| Backend API | FastAPI + uvicorn |
| Real-time streaming | Server-Sent Events (SSE) |
| CVE data | NVD API (nvd.nist.gov) |
| Version verification | npm registry API |
| Repository operations | Git + subprocess |
| Structured logging | Python logging + JSONL |
| Frontend | Vanilla HTML/CSS/JS |

---

## Ecosystem Support

| Ecosystem | Fix Method | Status |
|---|---|---|
| npm / Node.js | package.json overrides | ✅ Production |
| Maven / Java | pom.xml dependencyManagement | 🔄 In progress |
| Gradle | build.gradle resolutionStrategy | 📋 Planned |
| pip / Python | requirements.txt pin | 📋 Planned |
| Go modules | go.mod replace directive | 📋 Planned |

---

## Quick Start

```bash
# Clone
git clone https://github.com/zmax1360/PatchMind.git
cd PatchMind

# Install
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your tokens

# Run
python -m uvicorn api.server:app --reload --port 8000

# Open
open ui/index.html
```

---

## Configuration

```env
# Required
GITHUB_TOKEN=ghp_your_token_here
ANTHROPIC_API_KEY=sk-ant-your_key_here

# Optional - GitHub Enterprise
GITHUB_API_URL=https://your-ghe-hostname/api/v3

# Optional - defaults
GITHUB_OWNER=your_org
GITHUB_REPO=your_repo
```

---

## Compliance

PatchMind PR bodies include references to:

- **OSFI B-13** — Technology and Cyber Risk Management (Canadian banking)
- **PCI-DSS Requirement 6.3.3** — Secure development practices
- **FFIEC Cybersecurity Assessment** — Financial institution cyber controls

Every run generates:
- `.log` file — human-readable audit trail
- `.jsonl` file — structured machine-parseable audit trail
- Audit Trail ID (e.g. `PATCHMIND-0198`)

---

## Project Structure

```
PatchMind/
├── agents/
│   └── crew.py          # CrewAI agents, tasks, guardrails, pipeline
├── api/
│   └── server.py        # FastAPI backend, SSE streaming, approval endpoint
├── core/
│   ├── github_client.py # GitHub API client (alerts, PRs, branches)
│   ├── nvd_client.py    # NVD CVE database client
│   ├── repo_manager.py  # Git operations, ecosystem detection, test runner
│   └── logger.py        # Structured logging (.log + .jsonl per run)
├── ui/
│   └── index.html       # Single-file dashboard
├── logs/                # Audit trails (gitignored)
├── requirements.txt
└── .env.example
```

---

## Roadmap

- [ ] Maven/Java ecosystem support
- [ ] GitHub Enterprise (GHE) configuration
- [ ] Batch remediation (fix multiple alerts in one run)
- [ ] Slack/Teams notification on completion
- [ ] Historical metrics dashboard (cost per fix, time saved)
- [ ] SARIF input support (Checkmarx, Veracode, Snyk)
- [ ] Clojure/Leiningen support

---

## Why PatchMind Exists

Security teams at banks are drowning. The average financial institution has hundreds of open Dependabot alerts. Developers don't fix them because:

1. It's tedious manual work
2. They're not sure the fix is safe
3. Nobody wrote the compliance documentation

PatchMind automates all three. The human stays in the loop — they review the confidence score, read the diff, and click Approve. Everything else is handled.

**The remediation backlog is the $100M problem. PatchMind is the fix.**

---

## Built With

- [CrewAI](https://crewai.com) — Multi-agent orchestration
- [Anthropic Claude](https://anthropic.com) — LLM backbone
- [FastAPI](https://fastapi.tiangolo.com) — Backend API
- [NVD](https://nvd.nist.gov) — CVE database

---

*PatchMind AI — github.com/zmax1360/PatchMind*
