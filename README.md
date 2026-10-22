# SmartGuard AI — Module 1 & Module 2

Implementation of the first two functional modules of **SmartGuard AI** (AI-assisted
smart-contract vulnerability analysis), as specified in the project SRS.

| Module | Requirement | Delivered by |
| --- | --- | --- |
| **Module 1 — Contract Input** | Accept a Solidity `.sol` file (upload or paste), reject every other file type, enforce size limits and sanitise untrusted input | `backend/app/modules/contract_upload.py` |
| **Module 2 — Static Analysis** | Run the Slither detector suite and report every finding | `backend/app/modules/slither_scanner.py` |

The two modules are wired together by a FastAPI service (`backend/app/main.py`) and a
zero-dependency browser UI (`frontend/`).

---

## 1. Module 1 — Contract Input

### Accepted input

* A `.sol` file uploaded from the browser, **or**
* Solidity source pasted into the text area.

### Validation rules (SRS 4.1)

| Rule | Behaviour | Error code | HTTP |
| --- | --- | --- | --- |
| Only `.sol` accepted (case-insensitive) | Any other extension is rejected | `INVALID_EXTENSION` | 400 |
| File must not be empty | Blank / whitespace-only input rejected | `EMPTY_FILE` / `EMPTY_SOURCE` | 400 |
| Size limit 2 MB (configurable) | Oversized input rejected | `FILE_TOO_LARGE` / `SOURCE_TOO_LARGE` | 413 |
| Must be valid UTF-8 | Binary payloads rejected | `INVALID_ENCODING` | 400 |

### Security measures

* **Filename sanitisation** — directory components, control characters and shell
  metacharacters are stripped; the client-supplied extension is preserved so a
  `.py` file can never be laundered into a `.sol` file.
* **Isolated staging** — the source is written to a unique per-analysis file inside
  a dedicated temporary working directory (`/tmp/smartguard` by default) and removed
  when the analysis finishes.
* **Random analysis id** — every submission gets a UUID4 identifier.

## 2. Module 2 — Static Analysis (Slither)

### Detector coverage (SRS 4.2)

The scanner registers **all 57 High and Medium severity Slither detectors**
(29 High + 28 Medium). Informational and Optimization detectors are excluded, exactly
as the SRS prescribes.

`slither-analyzer==0.11.3` is pinned in `backend/requirements.txt` because it is the
only released version whose detector set matches the SRS counts:

| Slither version | High | Medium | High + Medium |
| --- | --- | --- | --- |
| 0.9.3 | 25 | 21 | 46 |
| 0.10.0 | 29 | 22 | 51 |
| 0.10.1 – 0.10.4 | 29 | 23 | 52 |
| **0.11.3 (pinned)** | **29** | **28** | **57** |

### Finding normalisation

Every raw Slither result is converted into a stable finding record:

`finding_id`, `detector`, `impact`, `severity`, `confidence`, `description`,
`contract`, `function`, `line`, `source_mapping`.

Impacts are mapped into the SmartGuard severity buckets
(`High → critical`, `Medium → high`, `Low → medium`, `Informational → low`,
`Optimization → informational`) and findings are sorted by severity, then by line.

### Compiler handling

`solc-select` provides the compiler. The scanner reads the contract's `pragma`
statement, maps it to the closest installed compiler version, and passes the resolved
absolute binary path to Slither. Compilation failures are reported as
`COMPILATION_FAILED` with the compiler message rather than crashing the service.

---

## 3. API

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/` | Service banner |
| `GET` | `/api/health` | Liveness probe |
| `GET` | `/api/detectors` | Registered detector count and the eligible High/Medium list |
| `POST` | `/api/analyze/upload` | Upload a `.sol` file — returns a receipt, scans in the background |
| `POST` | `/api/analyze/source` | Paste source — returns a receipt, scans in the background |
| `POST` | `/api/scan/sync` | Upload or paste source — returns the full report immediately |
| `GET` | `/api/analysis/{analysis_id}` | Fetch the report for a queued/completed analysis |

### Examples

```bash
# Reject a non-Solidity file
curl -F "file=@contract.py" http://127.0.0.1:8000/api/analyze/upload
# {"detail":{"code":"INVALID_EXTENSION","message":"Invalid file type 'contract.py'. ..."}}

# Scan a real contract and print the report
curl -X POST http://127.0.0.1:8000/api/scan/sync \
  -H "Content-Type: application/json" \
  -d '{"content": "<solidity source>", "filename": "Vault.sol"}'
```

---

## 4. Setup

### Prerequisites

* Python 3.9+
* macOS / Linux (the setup script targets POSIX shells)

### One-shot setup

```bash
bash scripts/setup.sh
```

The script creates `backend/.venv`, installs the pinned dependencies and installs the
`solc 0.8.20` compiler through `solc-select`.

### Manual setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
solc-select install 0.8.20
solc-select use 0.8.20
```

## 5. Running

```bash
# Terminal 1 — API
cd backend
.venv/bin/uvicorn app.main:app --reload --port 8000

# Terminal 2 — UI
cd frontend
python3 -m http.server 3000
```

Then open <http://localhost:3000>. The UI talks to the API on
`http://127.0.0.1:8000` (CORS for `localhost:3000` is pre-configured).

## 6. Tests

```bash
cd backend
.venv/bin/python -m pytest tests/ -q
```

The suite covers upload validation and rejection paths, filename sanitisation, the
57-detector eligibility check, real Slither scans against vulnerable and secure
sample contracts, compilation-failure handling, and every API endpoint.

## 7. Sample contracts

| File | Purpose |
| --- | --- |
| `samples/contracts/VulnerableVault.sol` | Reentrancy, controlled delegatecall, arbitrary ETH send, unchecked send |
| `samples/contracts/SecureVault.sol` | Checks-effects-interactions, owner-gated sweep — expected to produce no High/Medium findings |

## 8. Layout

```
.
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI app and endpoints
│   │   ├── core/
│   │   │   ├── config.py               # Environment-driven settings
│   │   │   └── models.py               # Pydantic response models
│   │   └── modules/
│   │       ├── contract_upload.py      # Module 1
│   │       └── slither_scanner.py      # Module 2
│   ├── tests/
│   ├── requirements.txt
├── frontend/
│   ├── index.html
│   ├── styles.css
│   └── app.js
├── samples/contracts/
└── scripts/setup.sh
```

## 9. Configuration

All settings can be overridden with environment variables (see `backend/app/core/config.py`):

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMARTGUARD_MAX_FILE_SIZE_MB` | `2` | Maximum accepted source size |
| `SMARTGUARD_MAX_SOURCE_CHARS` | `2097152` | Character cap for pasted source |
| `SMARTGUARD_WORK_DIR` | `/tmp/smartguard` | Temporary staging directory |
| `SMARTGUARD_SCAN_TIMEOUT` | `300` | Scan timeout in seconds |
| `SMARTGUARD_SOLC_VERSION` | `0.8.20` | Fallback compiler version |
| `SMARTGUARD_INCLUDED_IMPACTS` | `High,Medium` | Impact levels that are reported |
