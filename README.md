# ThreatGuard MCP 🛡️

A visually rich **Flask cybersecurity dashboard** and **real read-only MCP server** powered by the official CISA Known Exploited Vulnerabilities catalog.

## Features
- Animated original blue/cyan starfield and orbiting security motif, responsive dashboard
- Live vulnerability explorer, CVE details, vendor/product/keyword search, stats
- Standalone Python MCP server with 4 read-only tools (stdio transport)
- Input validation, 30 req/min local Flask API limiter, logging, security headers
- Cached official CISA KEV JSON, timeout and upstream failure handling
- Unit/security tests and self security review

## Requirements
Python 3.10+ and internet access for the official CISA feed.

## Run in VS Code (Windows PowerShell)
```powershell
cd ThreatGuard-MCP
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open **http://127.0.0.1:5000**. If PowerShell blocks activation, use `.venv\Scripts\python.exe app.py` and `.venv\Scripts\python.exe -m pip install -r requirements.txt` instead.

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Run MCP server separately
```bash
python mcp_server.py
```
MCP stdio is a protocol, **not a website**: it must be started by an MCP-compatible client. Example client configuration (replace path with your absolute project path):
```json
{
  "mcpServers": {
    "threatguard": {
      "command": "C:\\absolute\\path\\to\\ThreatGuard-MCP\\.venv\\Scripts\\python.exe",
      "args": ["C:\\absolute\\path\\to\\ThreatGuard-MCP\\mcp_server.py"]
    }
  }
}
```
The MCP tools are `get_latest_vulnerabilities`, `get_vulnerability`, `search_vulnerabilities`, and `get_catalog_stats`.

## API endpoints
- `GET /api/health`
- `GET /api/stats`
- `GET /api/latest?limit=25`
- `GET /api/search?q=Microsoft&limit=25`
- `GET /api/cve/CVE-2024-12345` (only returns a match if present in KEV)

## Run tests
```bash
python -m pytest -q
```

## Important security and data limitations
- This is a **local educational prototype**. Keep Flask bound to `127.0.0.1` by default. Do not expose it publicly without authentication, TLS, proxy configuration, and a production-grade distributed rate limiter.
- Flask's local HTTP API has rate limiting; the **stdio MCP tool interface also enforces 30 tool calls per minute per process**. These are educational, in-memory controls, not production-grade distributed limits.
- CISA KEV lists *known exploited* vulnerabilities, not every CVE. No CVSS scores are provided by this source. Do not label KEV entries as "critical" solely because they appear in the catalog.
- No LLM API key is required; MCP makes the data accessible to AI clients. No AI-generated conclusions are invented.
- See [`docs/SECURITY_REVIEW.md`](docs/SECURITY_REVIEW.md) for findings and mitigations.

## Source
Official feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

## Project layout
```
app.py               Flask UI + read-only HTTP API
mcp_server.py        MCP stdio tools
threat_service.py    Shared CISA KEV service
static/              CSS and JavaScript
templates/          Dashboard HTML
tests/              Automated tests
docs/               Self security review
```


## Data source popup (new)
On every fresh page open, a source-selection popup offers **Demo data**, **Upload your data**, or **Live CISA KEV**. The app never fetches live data until chosen. Demo records are illustrative. Upload accepts CSV or JSON with a `cveID` field (CVE-YYYY-NNNN), up to 20,000 records and 25 MB. Uploads are validated in memory and returned for browser preview; no uploaded dataset is stored on disk or added to CISA. Switching sources clears the displayed data. The server-side MCP tools still access the official CISA source, independent of browser demo/upload selections.

### CSV upload troubleshooting (updated)

Choose **Upload your data** and select a `.csv` or `.json` file. CSV files must have a CVE ID column; accepted spellings include `cveID`, `CVE ID`, `cve_id`, and `CVE-ID`. Other recognized fields (for example `Vendor`, `Product`, `Description`, `Date Added`) are optional. UTF-8, UTF-8 BOM, and Windows CP1252 CSV files are supported, as are comma, semicolon, tab and pipe separators. Uploads are limited to 25 MB and 20,000 records. Errors identify missing columns and invalid CVE IDs by row. Uploaded content is only previewed in memory and is not persisted.


Large CSV uploads: file cap 25 MB and 20,000 records. Requests have a 26 MiB multipart cap. The entire preview is returned to the browser; for much larger datasets, implement pagination and streaming rather than removing limits.

## Groq AI Chat

1. Install dependencies: `pip install -r requirements.txt`
2. Copy `.env.example` to `.env` and replace `your_groq_api_key_here` with your Groq key.
3. Run `python app.py` and open `http://127.0.0.1:5000/#chat`.
4. Use **Groq AI Chat** in the left sidebar. The key is never exposed to browser JavaScript.

The assistant sends your question and up to 12 selected demo/upload records to Groq; uploaded records are untrusted and may contain sensitive information. The AI chat is a POST endpoint and does not modify the CISA catalog. Do not expose this demo publicly without authentication and production controls. Model availability and Groq service access are required for responses.
