# SentinelFIM

SentinelFIM is a defensive endpoint security tool that detects unauthorized file changes by comparing current SHA-256 hashes with a trusted baseline. It demonstrates practical blue-team skills relevant to SOC Analyst, Security Analyst, and cybersecurity internship roles.

## Why this project matters

Attackers may modify startup scripts, configuration files, executables, web applications, or security controls to maintain access or manipulate systems. File Integrity Monitoring helps defenders identify these changes and investigate them before further damage occurs.

## Security capabilities

- Recursive SHA-256 file baselining
- Added, modified, and deleted file detection
- HMAC-SHA256 baseline signing and tamper detection
- Higher risk scores for scripts, executables, credentials, and configuration files
- MITRE ATT&CK mapping to T1565.001, Stored Data Manipulation
- Configurable glob exclusions
- Symbolic-link exclusion to avoid unsafe traversal
- Analyst-focused terminal output
- Structured JSON alert reports for SIEM ingestion
- Meaningful process exit codes for automation

## Quick start

### Requirements

- Python 3.10 or later
- No third-party runtime dependencies

```bash
git clone https://github.com/Khayaguzu/sentinelfim.git
cd sentinelfim
python -m venv .venv
```

On Windows, activate the environment and install the project:

```powershell
.venv\Scripts\activate
python -m pip install -e .
```

Create a protected baseline:

```powershell
$env:SENTINELFIM_SIGNING_KEY = "use-a-long-random-secret"
sentinelfim baseline C:\path\to\monitor --output baseline.json --exclude "*.log"
```

Check for unauthorized changes:

```powershell
sentinelfim check C:\path\to\monitor --baseline baseline.json --report reports\alerts.json --exclude "*.log"
```

Example output:

```text
Detected 3 integrity change(s)

SEVERITY   RISK   CHANGE     PATH
CRITICAL   90     MODIFIED   startup.ps1
MEDIUM     65     DELETED    settings.json
MEDIUM     55     ADDED      unexpected.txt
```

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Scan completed, no changes found |
| 1 | Configuration, baseline, or file-system error |
| 2 | One or more integrity changes detected |

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite verifies added, modified, and deleted file detection, clean scans, high-value risk scoring, exclusions, and signed-baseline tamper detection.

## Analyst workflow

1. Select critical directories and define expected exclusions.
2. Create a baseline on a known-clean endpoint.
3. Store the baseline securely and protect it with a signing key.
4. Run scheduled integrity checks.
5. Prioritize high-risk changes to scripts, executables, credentials, and configuration.
6. Validate the responsible user or process through endpoint and audit logs.
7. Contain the host and restore trusted files when changes are unauthorized.
8. Rebuild the baseline only after approving legitimate changes.

## Limitations

- SentinelFIM identifies file changes, but does not prove malicious intent.
- A local attacker with sufficient privileges may interfere with monitoring.
- Production use should store the baseline and signing key outside the monitored host.
- Continuous monitoring and operating-system audit-log integration are roadmap items.

## Roadmap

- Scheduled continuous monitoring
- Windows Event Log and Linux auditd correlation
- Email, webhook, and SIEM alert delivery
- YARA scanning for newly added or modified files
- Authenticated remote baseline storage
- Docker packaging and cross-platform release builds

## Responsible use

Monitor only systems and files that you own or are authorized to protect. Do not collect or publish sensitive file contents.

## License

Licensed under the MIT License.
