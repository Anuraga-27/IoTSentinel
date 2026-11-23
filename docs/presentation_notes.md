# IoTSentinel — Presentation notes and viva prep

All numbers below were re-run on 22 Nov 2026 from this repository
(`unittest`, `run_validation.py`, `threshold_sweep.py`, `run_pcap_validation.py D:\CIC\pcap`).

## Fix before presenting

| Slide | Says | What the code/output shows | Suggested change |
|---|---|---|---|
| 3 | "five attacks, each in a loud and a slow form" | ARP spoofing has no slow form (`SLOW_ATTACKS["arp_spoof"]` reuses the loud one: a single forged frame can't be slowed) | "five attacks, four of them also in a slow form" |
| 11 | port-scan fix cut false alarms "with no attack lost" | True, but time to detect the real port scan rose from **9.4 s to 42.0 s** | Add "(detection of the real scan slowed from 9 s to 42 s)" — better you say it than the examiner |
| 9 | "18/18 unit tests" | Two tests added on 22 Nov (slow flood and slow botnet are missed), so it is now **20/20**, and all four slow variants are unit-tested | "20/20" |
| 14 | "182k records per second" | Now reproducible with `python validation/benchmark.py`: **216–225k records/s** (240,000 flood records, full pipeline, no SQLite) | Keep 182k as a conservative figure, or say "over 200k"; cite the benchmark script |
| 13 | slow counter dropped throughput "to 12k records/s" | Can't be re-checked — the old counter is no longer in the code | Fine to keep; just know it's a historical figure |

Checked and correct: 344,574 real packets (sum of the six captures),
48 sweep settings, 139 port-scan / 147 total benign false alarms before the fix, 8 after (20.4/hour),
4 of 5 attacks caught on PCAP, flood caught in 0.03 s, 94% (139/147).

## Speaker notes, per slide

1. **Title.** Introduce the team. One line: "a simple, rule-based IDS for home and hostel IoT networks, tested on real traffic."
2. **Problem.** IoT devices ship with default passwords and open ports; no one is watching. Routers don't alert, devices have no screen, enterprise IDS is too heavy, and there's no history.
3. **Goal & objectives.** Stress the last clause of the goal: accuracy *measured, not assumed*. That sets up slides 9–11.
4. **Scope.** Say the safety line aloud: all attack traffic is generated in memory, nothing is sent on a real network. Out of scope: real hardware capture, blocking, ML, cloud.
5. **Architecture.** Three layers: sources (simulator, attacks, CIC dataset) → processing (collector, rule engine, grouper, thresholds from `rules.yaml`) → output (SQLite, Streamlit). The same pipeline serves the dashboard and the tests.
6. **Data flow.** Each record is routed by event type: `packet` → flooding and port scan, `login_failed` → brute force, `arp_announce` → ARP tracker, telnet `connect` → botnet. All rules feed one incident grouper.
7. **Five rules.** Walk the table. Every rule is a counter over a sliding window; thresholds live in YAML so tuning needs no code change.
8. **Less noise.** ARP: a new MAC opens a 30 s grace window; if only it keeps appearing it's a DHCP change, if a second MAC competes it's spoofing. Grouping: same rule + source + target within 60 s is one incident; severity escalates at 3, 6 and 10 repeats. A 10 s flood gives one critical incident instead of ~13,000 raw violations (the validation run raises 13,204 violations → 7 incidents).
9. **Four layers of testing.** 20 unit tests, simulated loud vs slow attacks, 344,574 real packets, 48-point threshold sweep.
10. **Thresholds are trade-offs.** Low threshold: firmware burst is a false alarm. High threshold: slow flood is missed. Packet count alone can't tell a big download from a flood → per-device baselines are the next step.
11. **Real traffic found a flaw.** Port scan counted server replies → 139 false alarms in 23.5 min. Counting only connection attempts → 8 benign false alarms total, every attack still caught (scan detected later: 42 s vs 9 s). Mirai miss is a category mismatch: CIC's Mirai capture is a flood, our rule looks for telnet spreading — and the flooding rule did fire on it.
12. **Dashboard.** Point at camera-1 turning red, the traffic spike, and the single critical incident with count 5945.
13. **Lessons.** Self-generated traffic flatters the detector; define exactly what a rule counts; test the test harness.
14. **Conclusion.** 4/5 real attacks, 20 false alarms/hour, 180k+ records/s. A proof of concept, not a replacement for professional tools.

## Likely viva questions

**Why rules and not machine learning?**
Explainable, no training data needed, every alert says exactly which threshold was crossed, and thresholds can be tuned by a non-expert. ML was out of scope; per-device baselines are the planned bridge.

**Your sweep shows a flood threshold of 5000 has the same detection rate as 500 and zero false alarms. Why keep 500?**
Honest answer: on our small corpus (2 flood windows, 3 benign cases) 500 is not the best setting — 1500–4000 give 1 false alarm, 5000 gives 0, all with the same 0.5 detection. 500 comes from the proposal and is the safer choice for slower real floods; the corpus is too small to pick a threshold from. This is exactly why we say thresholds are trade-offs.

**How is brute force detected in the packet captures, when login results are encrypted?**
By proxy: the PCAP loader counts new connections to login ports (21, 22, 23, 2323) as attempts. That's also why the port-scan capture shows 6 brute-force alerts — the scanner touches those ports.

**What are the 8 remaining benign false alarms?**
4 ARP: one device (192.168.137.249) answers ARP with two MACs — whitelistable once confirmed legitimate. 4 flooding: two large cloud transfers to one device — the real-world version of the firmware-burst case.

**Why did the ARP rule score 100% in simulation?**
The simulated spoof sends the forged and genuine frames 1 s apart, inside the 30 s grace window. The sweep shows any grace under 1.5 s misses it, and a grace of 0 disables contention detection entirely. On real traffic (MITM capture) it fired in 8.5 s.

**Why did the CSV (flow) results show 1.00 recall but you present PCAP results?**
The CSVs only hold aggregated flow features, so the loader had to rebuild packets with our own generators — partly circular. PCAPs give real IPs, ports, MACs and timing, so they are the independent test.

**Couldn't an attacker just stay under the threshold?**
Yes — that's what the slow variants show (4 of 4 missed). Fixed thresholds have a detection floor; longer windows or baselines raise the cost for the attacker but don't remove it.

**How fast is it?**
Over 180k records/s on one laptop with the full pipeline; `validation/benchmark.py` measured 216–225k/s on 22 Nov. Alerts reach the dashboard within the 5 s objective.

**Does it block attacks?**
No — detection and alerting only. Blocking was out of scope; it would need router integration and carries a false-positive risk.

**What would you do next?**
Per-device traffic baselines instead of fixed flood thresholds; a Mirai-flood signature; live capture from a real access point.
