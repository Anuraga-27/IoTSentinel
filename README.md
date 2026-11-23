# IoTSentinel

A rule-based intrusion detection system for a simulated IoT network, with a live monitoring dashboard.

Six virtual devices produce normal traffic. Five attack scripts inject attack traffic. A rule engine checks every record against five threshold rules inside sliding time windows. Each alert is saved to SQLite and shown on a Streamlit dashboard.

All traffic is simulated in memory. Nothing here sends packets on a real network.

## Setup

You need Python 3.10 or later.

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

On macOS or Linux, activate with `source .venv/bin/activate` instead.

If Windows says `python` or `pip` is not recognised, Python was installed without "Add python.exe to PATH". Re-run the installer, choose Modify, and tick that option. Alternatively, call Python by its full path, for example `%LOCALAPPDATA%\Programs\Python\Python314\python.exe -m pip install -r requirements.txt`.

If creating `.venv` fails with `No module named 'pip._internal.utils'`, the project folder's path is too long for Windows. Move the folder somewhere shorter, such as `C:\iotsentinel`, or skip the virtual environment and install straight into Python.

## Run it

On Windows, double-click the launchers in the project folder:

- `run_dashboard.bat` starts the dashboard. Then open http://localhost:8501 in your browser.
- `run_validation.bat` runs the tests, prints the validation report, and writes the threshold-sweep plots.

Both launchers use the project's own environment in `.venv`. Create it once with `python -m venv .venv` and `.venv\Scripts\python.exe -m pip install -r requirements.txt`.

From a terminal, run these commands in the project folder:

| What | Command |
|---|---|
| Live dashboard (demo scenarios A, B and C) | `streamlit run src/iotsentinel/dashboard.py` |
| Repeatable tests | `python -m unittest discover -s tests` |
| Precision, recall and false-positive report | `python validation/run_validation.py` |
| Same report, with a CIC IoT 2023 subset added | `python validation/run_validation.py --cic-csv path/to/DDoS-TCP_Flood.csv` |
| Threshold sweep (CSV and PNG plots) | `python validation/threshold_sweep.py` |
| Test on real CIC packet captures | `python validation/run_pcap_validation.py D:\CIC\pcap` |
| Throughput under flood load (records per second) | `python validation/benchmark.py` |

### Demo walkthrough

1. Start the dashboard and press **Start monitoring**. All six devices stay green (scenario A).
2. Pick an attack and a device in the sidebar, then press **Launch**. Within a few simulated seconds the device turns red, labelled ALERT, and an incident appears in the log (scenario B).
3. When the attack's duration ends, the device returns to normal after 15 seconds. The incident stays in the log (scenario C).

## Project report

The report is `docs/IoTSentinel_Project  Report.docx` (note the two spaces before "Report"; 15 pages as PDF), with a PDF copy alongside. It covers the goal, requirements, design (architecture, data flow, flowchart), program screenshots, test output screenshots and lessons learned. `docs/IoTSentinel_Project_Report.docx` is the earlier, longer 23-page version.

To rebuild it after changing results, run `.venv\Scripts\python.exe docs\report\make_figures.py` and `.venv\Scripts\python.exe docs\report\make_screenshots.py`, then `node build_report.js` from `docs\report`. The build writes a fresh `docs/IoTSentinel_Project_Report_Short.docx`; it does not overwrite the finished report above, so copy across any edits made in Word. Then open the `.docx` in Word, right-click the contents table and choose Update Field. The screenshots read the program output saved in `docs\report\output`.

## Layout

```
rules/rules.yaml               thresholds, ARP grace period and whitelist, grouping settings
src/iotsentinel/
  devices.py                   the six virtual devices
  device_simulator.py          normal traffic, plus the hard benign cases
  attack_simulator.py          five attacks, each with a loud and a slow variant
  flow_collector.py            drops malformed records
  rule_engine.py               five rules, ARP tracker, incident grouper
  alert_store.py               SQLite incident store
  pipeline.py                  collector -> engine -> grouper -> store
  dashboard.py                 Streamlit dashboard
validation/
  scenarios.py                 labelled test corpus with ground-truth windows
  metrics.py                   matches incidents to ground truth and scores them
  run_validation.py            prints the per-attack report
  threshold_sweep.py           detection rate vs false alarms per rule
  cic_loader.py                CIC IoT 2023 CSV -> IoTSentinel records
  pcap_loader.py               CIC IoT 2023 packet captures -> IoTSentinel records
  run_pcap_validation.py       per-capture detection report on real packets
  benchmark.py                 throughput under flood load, in records per second
tests/test_rules.py            unit tests
tests/test_pcap.py             packet-reader and port-scan-counting tests
```

## Detection rules

| Attack | What the rule checks | Default threshold |
|---|---|---|
| Flooding (DoS) | Packets arriving at one device | > 500 in 10 s |
| Port scan | Distinct ports contacted by one source | > 20 in 10 s |
| Brute-force login | Failed logins from one source | > 5 in 60 s |
| ARP spoofing | Two MACs contending for one IP inside the grace period | 30 s grace |
| Botnet behaviour | Distinct telnet targets contacted by one device | > 10 in 30 s |

Every threshold lives in `rules/rules.yaml`, so you can change it without editing code.

## How the review feedback is addressed

### 1. Self-generated traffic proves little: test on CIC IoT 2023

`validation/run_validation.py` reports TP, FN, FP, recall and precision for each attack, and a false-positive rate across the benign cases. It always runs the built-in labelled corpus. Each `--cic-csv` file you pass is added to the same scoring run.

**What you need to do:** download a few per-category CSVs from the CIC IoT 2023 page (https://www.unb.ca/cic/datasets/iotdataset-2023.html). Pick one benign file and one file for each attack type, for example `BenignTraffic.csv`, `DDoS-TCP_Flood.csv`, `Recon-PortScan.csv`, `DictionaryBruteForce.csv`, `MITM-ArpSpoofing.csv` and `Mirai-greeting_flood.csv`. The loader works out each file's category from its filename.

**Limitation to state in your report:** CIC IoT 2023 ships aggregated flow features, such as rate, flag counts and protocol indicators. It does not ship raw packets with ports and MAC addresses, which is what the rules read. `cic_loader.py` expands each row back into a short burst of raw events that matches the row's rate and protocol, and keeps the row's label as ground truth. That makes the CIC numbers an indication of whether the thresholds sit at the right scale for real traffic. They are not a packet-exact replay. The docstring at the top of `cic_loader.py` explains the mapping.

**Results on real CIC data.** These come from the first 300 rows of one file per category: `BenignTraffic`, `DDoS-TCP_Flood`, `Recon-PortScan`, `DictionaryBruteForce`, `MITM-ArpSpoofing` and `Mirai-greeth_flood`. The samples are in `D:\CIC`. The files do have the `Rate` and `Number` columns.

| Category | Windows | Detected | Recall |
|---|---|---|---|
| Flooding | 300 | 300 | 1.00 |
| Port scan | 300 | 0 | 0.00 |
| Brute force | 300 | 300 | 1.00 |
| ARP spoofing | 300 | 300 | 1.00 |
| Botnet (Mirai) | 300 | 300 | 1.00 |
| Benign | 300 | 0 false alarms | — |

How to read these numbers honestly:

- **Port scan scores 0 because of the mapping, not the rule.** The loader uses `Number` as the count of ports scanned. In this dataset `Number` counts packets in a flow window, so each row becomes about 10 ports, below the threshold of 20. The CSVs contain no port information at all.
- **The 1.00 scores are partly built in.** The loader rebuilds each attack row with our own attack generators, sets minimum rates, and caps benign traffic at 5 packets per second. The CIC numbers therefore show that the thresholds suit the dataset's rates. They are not an independent test of detection.
- **For an independent test, use the PCAP results below.**

**Results on real packets (PCAP).** `validation/pcap_loader.py` reads the dataset's raw packet captures, using only Python's standard library. Each packet becomes a record with the real IPs, ports, MACs and timing, and nothing is rebuilt by our attack scripts. Run it with `python validation/run_pcap_validation.py D:\CIC\pcap`. The samples are the first 9–22 MB of one capture per category, and each one runs through its own fresh pipeline.

| Capture | Expected rule | Caught? | Time to detect | Other alerts |
|---|---|---|---|---|
| Benign (23.5 min, 84,076 packets) | — | — | — | 8 false alarms (20 per hour) |
| DDoS TCP flood | flooding | yes | 0.03 s | 0 |
| Dictionary brute force | brute_force | yes | 42.6 s | 2 |
| MITM ARP spoofing | arp_spoof | yes | 8.5 s | 2 |
| Recon port scan | port_scan | yes | 42.0 s | 18 |
| Mirai greeth flood | botnet | **no** | — | 2 (flooding) |

What real traffic showed, worth reporting:

- **The port-scan rule as proposed fails on real traffic.** Counting every packet, it raised **139 false alarms in 23.5 minutes** of benign traffic, because a server's replies go to many random client ports. Setting `count_only_connection_attempts: true` in `rules.yaml` counts only TCP SYNs, plus UDP sent to the lower of its two ports. That cut benign false alarms from 147 to 8, and every attack it caught before is still caught.
- **The remaining benign false alarms have two causes.** One device (192.168.137.249) answers ARP with two MACs, which accounts for 4 alarms; adding it to the ARP `whitelist` silences them once someone confirms the device is legitimate. Two large cloud transfers to one device account for the other 4, which is the real-world version of the firmware-burst case: a raw packet count can't tell a big download from a flood.
- **The Mirai miss is a category mismatch.** CIC's Mirai files record floods launched by Mirai. The botnet rule watches for Mirai spreading itself over telnet, and this capture contains no telnet. The flooding rule fired instead.
- **Brute force is detected by proxy.** Whether a login failed lives inside encrypted application data, so the loader counts new connections to login ports (21, 22, 23, 2323). This also explains the 6 brute-force alerts in the port-scan capture, where the scanner touches those ports.
- **The other alerts in attack captures** are mostly background traffic recorded alongside the attack, such as busy hosts tripping the flooding rule. They are not proof the rule is wrong, but they are not true detections of the labelled attack either.

### 2. Threshold sweep, including hard benign cases and slow attacks

`validation/threshold_sweep.py` varies one setting at a time: each rule's threshold, and the ARP grace period. It reruns the same corpus at each value and writes `validation/out/threshold_sweep_results.csv`, plus one detection-rate-against-false-alarms PNG per rule.

The corpus deliberately includes cases the rules handle badly:

| Case | Type | Rule it stresses | What to expect |
|---|---|---|---|
| Firmware-update burst | Benign | Flooding | Looks like a flood by packet count. Expect a false alarm at any threshold low enough to catch real floods. |
| Camera stream | Benign | Port scan, flooding | Always one port, so the port-scan rule stays quiet. Its volume can still trip the flooding rule. |
| DHCP reassignment | Benign | ARP | One clean MAC change with no contender. The grace period keeps it silent. |
| Slow flood, scan, brute force, botnet | Attack | One rule each | Kept under the default thresholds. Expect misses. These show where fixed thresholds stop working. |

Expect the sweep to show that **no single flooding threshold separates a dense firmware push from a real flood by packet count alone**. That is a real limit of the approach, and worth saying in the report. A rate compared against each device's own normal baseline is the natural next step.

### 3. Less alert noise

- **ARP grace period and whitelist** (`ArpTracker` in `rule_engine.py`). A new MAC for a known IP opens a grace window, and nothing fires yet. If the new MAC keeps appearing alone, it is accepted quietly once the window closes. If a second MAC claims the IP while the window is open, that two-way contention is the signature of real spoofing, so a critical alert fires. Pairs listed under `whitelist` in `rules.yaml` never alert. A grace period of 0 turns off contention detection. The sweep shows this.
- **Incident grouping with severity** (`IncidentGrouper`). Repeated violations with the same rule, source and target within 60 seconds fold into one incident. The incident keeps a count, and its severity rises as the count passes the `escalation_repeat_counts` settings. A 10-second flood produces one critical incident, not thousands of alerts.
- **Flood attribution.** The flooding rule names the top sender in the window, so a device's own background traffic is not logged as a second attacker.

## Scope

Out of scope, as in the proposal: real hardware and live capture, automatic blocking, machine-learning detection, and cloud deployment or user accounts.
