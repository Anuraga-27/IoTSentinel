# IoTSentinel — project notes for Claude

Rule-based intrusion detection system for a simulated IoT network, with a
live Streamlit dashboard. College project, Sathyabama Institute, Team 2
(5 members). Presented November 2026.

Project folder: `D:\IoTSentinel`
GitHub: https://github.com/Anuraga-27/IoTSentinel (public)
Hosted app: https://iotsentinel-rreqchtfym3hsndfg9zrfw.streamlit.app/

## What it does

Six virtual IoT devices generate normal traffic. Five attack generators
inject attack traffic. A rule engine checks every record against five
threshold rules inside sliding time windows. Repeated violations are
grouped into incidents, stored in SQLite and shown on a dashboard.

Nothing touches a real network — all traffic is generated in memory.

## Commands

Always use the project's own Python. In PowerShell a relative path needs
a leading `.\`, or the command is "not recognized".

```powershell
cd D:\IoTSentinel
.\.venv\Scripts\python.exe -m streamlit run src/iotsentinel/dashboard.py   # dashboard at localhost:8501
.\.venv\Scripts\python.exe -m unittest discover -s tests -v                # 21 tests
.\.venv\Scripts\python.exe validation/run_validation.py                    # precision/recall report
.\.venv\Scripts\python.exe validation/run_pcap_validation.py D:\CIC\pcap   # real packet captures
.\.venv\Scripts\python.exe validation/threshold_sweep.py                   # sweep + PNG plots
.\.venv\Scripts\python.exe validation/benchmark.py                         # throughput
.\run_validation.bat                                                        # all of the above
```

Git is installed at `C:\Program Files\Git\cmd\git.exe` and the GitHub CLI
at `C:\Program Files\GitHub CLI\gh.exe`. Neither is reliably on PATH in a
fresh terminal — prepend those folders if `git` is not recognised.

## Layout

```
rules/rules.yaml              all thresholds, ARP grace period, whitelist, grouping
src/iotsentinel/
  devices.py                  the six virtual devices
  device_simulator.py         normal traffic + hard benign cases
  attack_simulator.py         five attacks, loud and slow variants
  flow_collector.py           drops malformed records
  rule_engine.py              five rules, ArpTracker, IncidentGrouper
  alert_store.py              SQLite incident store
  pipeline.py                 collector -> engine -> grouper -> store
  dashboard.py                Streamlit dashboard (the only runnable entry point)
validation/                   scenarios, metrics, CIC loaders, sweep, benchmark
tests/                        21 unit tests
docs/presentation_notes.md    speaker notes + viva questions
```

There is no `main.py`. `dashboard.py` must be started through Streamlit,
not with `python dashboard.py`.

## Key facts (all re-verified 22–23 Nov 2026)

- **21 unit tests**, all passing, ~0.2 s.
- **Five rules**: flooding >500/10 s, port scan >20/10 s, brute force
  >5/60 s, ARP spoofing (contention inside a 30 s grace window), botnet
  >10 telnet hosts/30 s.
- **Real packet captures (CIC IoT 2023)**: 4 of 5 attacks detected.
  Flooding in 0.03 s. Mirai missed — CIC's Mirai capture is a flood, while
  the botnet rule looks for telnet spreading.
- **Port-scan fix**: counting only connection attempts cut benign false
  alarms from 147 to 8 (20.4/hour). Cost: detection of the real scan
  slowed from 9.4 s to 42.0 s.
- **Throughput**: 206k–225k records/s on an idle laptop. Drops to ~89k
  when the machine is busy. The deck's 182k is deliberately conservative.
- **Incident grouping**: a 15 s flood produces ~11,600 violations and
  exactly 1 incident. This contrast is the best moment in the demo.

## Gotchas

- **PowerShell needs `.\`** before a relative executable path.
- **Reset** now clears the alert log (fixed 23 Nov). Before that it only
  cleared the session while SQLite kept every old incident.
- **The alert log is shared between viewers** of the hosted app — it lives
  in one SQLite file on the server, not per visitor. It also resets
  whenever the app sleeps.
- **`.streamlit/config.toml` must not set `server.address`/`headless`** —
  that breaks hosted deployments. Local-only behaviour comes from
  `run_dashboard.bat` passing `--server.address localhost`.
- **`use_container_width` is removed** from current Streamlit; use
  `width="stretch"`.
- **`.gitignore` covers `*.db` and `*.db.*`** — don't let `git add -A`
  sweep database files in.
- **Commits use** `319865730+Anuraga-27@users.noreply.github.com`, not the
  personal Gmail. Keep it that way; the repo is public.

## Deck corrections still outstanding

The presentation PDF has not been updated. It needs:

| Slide | Change |
|---|---|
| 3 | "five attacks, each loud and slow" → only four have slow variants; ARP spoofing can't be slowed |
| 9 | "18/18 unit tests" → **21/21** |
| 11 | add that the port-scan fix slowed real-scan detection from 9 s to 42 s |
| 13 | "12k records/s" describes code that no longer exists — historical figure only |
| 14 | be ready to say 182k came from `validation/benchmark.py` |

`docs/report/output/tests.txt` also still shows the old 18-test run, so
the report's test screenshot is stale.

## Demo script

1. Press **Reset** (clean log), then **Start monitoring** — all six green,
   13–14 records/s.
2. Pick an attack and an explicit device (not "(random)"), press
   **Launch**. Traffic jumps to ~800/s and the device turns red.
3. Scroll to the alert log: **~11,600 violations, 1 incident**. Say both
   numbers out loud — that is the noise-reduction result.
4. After the attack ends, the device returns to green in 15 s and the
   incident stays logged.

Launch takes ~2 seconds to show the red state. Don't double-click.

## Scope (stated in the proposal)

Out of scope: real hardware capture, automatic blocking, machine-learning
detection, cloud deployment and user accounts. Note the project *was*
later deployed to Streamlit Cloud, which goes beyond the stated scope —
either present it as going further than proposed, or leave it out.
