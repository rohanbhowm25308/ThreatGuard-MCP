# ThreatGuard Advanced Features

- **AI Threat Risk Predictor:** transparent heuristic triage score (55 base for selected CVE, +25 known ransomware, +15 overdue, +5 documented required action). Not CVSS, EPSS, or an exploitation probability.
- **Investigation Lab:** browser-rendered relationship cards and optional Groq defensive briefing; uses current demo/upload records.
- **Security Reports:** POST /api/security-report builds PDF in memory for 1–30 validated CVE records. No persistence; install reportlab.

Live CISA mode intentionally does not forward the catalog to these workspaces; choose demo or upload a dataset. Groq requires a valid key in .env; never commit it.
