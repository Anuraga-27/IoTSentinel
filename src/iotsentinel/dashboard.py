"""Streamlit live dashboard: device status, live traffic chart, alert log.

Run with:  streamlit run src/iotsentinel/dashboard.py
"""

from __future__ import annotations

import random
import sys
import time
from pathlib import Path

# `streamlit run src/iotsentinel/dashboard.py` puts this file's folder on the
# path, not src/, so make the package importable without an install.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from iotsentinel import attack_simulator as atk
from iotsentinel import device_simulator as dev
from iotsentinel.alert_store import AlertStore
from iotsentinel.devices import DEVICES
from iotsentinel.pipeline import Pipeline, load_rules

TICK = 1.0            # simulated seconds advanced per Streamlit rerun
ALERT_CLEAR_S = 15.0   # how long a device stays red after its last incident

st.set_page_config(page_title="IoTSentinel", layout="wide")


def init_state() -> None:
    if "pipeline" in st.session_state:
        return
    store = AlertStore("iotsentinel_dashboard.db")
    st.session_state.pipeline = Pipeline(load_rules(), store=store)
    st.session_state.store = store
    st.session_state.sim_time = time.time()
    st.session_state.start_time = st.session_state.sim_time
    st.session_state.running = False
    st.session_state.rng = random.Random(42)
    st.session_state.attack_queue = []       # pre-generated attack records, by time
    st.session_state.traffic_history = []    # list of (sim_time, packets_this_tick)
    st.session_state.total_packets = 0


def advance_one_tick() -> None:
    pl: Pipeline = st.session_state.pipeline
    rng: random.Random = st.session_state.rng
    t0 = st.session_state.sim_time
    t1 = t0 + TICK

    records = list(dev.normal_traffic(TICK, t0, rng=rng))

    queue = st.session_state.attack_queue
    due = 0
    while due < len(queue) and queue[due].timestamp < t1:
        due += 1
    records.extend(queue[:due])
    del queue[:due]

    records.sort(key=lambda r: r.timestamp)
    new_incidents = pl.process_stream(records)

    st.session_state.total_packets += len(records)
    st.session_state.traffic_history.append((t1, len(records)))
    if len(st.session_state.traffic_history) > 120:
        st.session_state.traffic_history.pop(0)

    st.session_state.sim_time = t1
    return new_incidents


def launch_attack(name: str, duration: float, device_name: str | None) -> None:
    # Generate the whole attack once, then release it tick by tick. Rebuilding
    # it every tick would restart scans at port 1 and botnets at host 1.
    gen = atk.ATTACKS[name]
    new = list(gen(duration, st.session_state.sim_time,
                   device_name=device_name, rng=st.session_state.rng))
    st.session_state.attack_queue = sorted(st.session_state.attack_queue + new,
                                           key=lambda r: r.timestamp)


init_state()
pl: Pipeline = st.session_state.pipeline

st.title("IoTSentinel — Live Monitoring Dashboard")
st.caption("Rule-based intrusion detection for a simulated IoT network")

with st.sidebar:
    st.header("Control panel")
    if st.button("Start monitoring" if not st.session_state.running else "Pause"):
        st.session_state.running = not st.session_state.running

    st.subheader("Launch an attack")
    attack_choice = st.selectbox("Attack", list(atk.ATTACKS.keys()))
    device_choice = st.selectbox("Target / source device", ["(random)"] + [d.name for d in DEVICES])
    duration = st.slider("Duration (s)", 5, 60, 15)
    if st.button("Launch"):
        launch_attack(attack_choice, duration,
                       None if device_choice == "(random)" else device_choice)
        st.session_state.running = True

    if st.button("Reset"):
        # Empty the stored incidents too: clearing only the session leaves
        # the alert log showing incidents from earlier runs.
        st.session_state.store.clear()
        st.session_state.store.close()
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

if st.session_state.running:
    advance_one_tick()

now = st.session_state.sim_time

st.subheader("Device status")
cols = st.columns(len(DEVICES))
for col, device in zip(cols, DEVICES):
    status = pl.device_status(device.name, now, clear_after_s=ALERT_CLEAR_S)
    color = "#d33" if status == "alert" else "#2a8"
    label = "ALERT" if status == "alert" else "normal"
    col.markdown(
        f"<div style='padding:10px;border-radius:8px;background:{color};"
        f"color:white;text-align:center'><b>{device.name}</b><br>{label}</div>",
        unsafe_allow_html=True,
    )

st.subheader("Live traffic")
hist = st.session_state.traffic_history
if hist:
    df = pd.DataFrame(hist, columns=["t", "packets"])
    df["t"] = df["t"] - st.session_state.start_time
    fig = go.Figure(go.Scatter(x=df["t"], y=df["packets"], mode="lines", line=dict(color="#2a8")))
    fig.update_layout(height=250, margin=dict(l=10, r=10, t=10, b=10),
                       xaxis_title="seconds since start", yaxis_title="records per second")
    st.plotly_chart(fig, width="stretch")
else:
    st.info("Press Start monitoring to begin generating traffic.")

st.subheader("Alert log (incidents)")
rows = st.session_state.store.recent(limit=100)
if rows:
    df = pd.DataFrame(rows).sort_values("last_seen", ascending=False)
    for col in ("first_seen", "last_seen"):
        df[col] = df[col].map(lambda s: time.strftime("%H:%M:%S", time.localtime(s)))
    df = df[["last_seen", "rule", "severity", "target", "source", "count", "first_seen"]]
    st.dataframe(df, width="stretch", hide_index=True)
else:
    st.caption("No incidents recorded yet.")

col1, col2, col3 = st.columns(3)
col1.metric("Packets processed", st.session_state.total_packets)
col2.metric("Violations detected", pl.violations_seen)
col3.metric("Incidents (grouped alerts)", st.session_state.store.count())

if st.session_state.running:
    time.sleep(0.5)
    st.rerun()
