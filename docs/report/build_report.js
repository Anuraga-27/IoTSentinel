// Builds docs/IoTSentinel_Project_Report.docx from the project's measured results.
// Run from docs/report:  node build_report.js   (after make_figures.py and make_screenshots.py)
const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow,
  TableCell, WidthType, ShadingType, BorderStyle, ImageRun, TableOfContents,
  Footer, PageNumber, LevelFormat,
} = require("docx");

const FIG = path.join(__dirname, "figures");
const OUT = path.join(__dirname, "..", "IoTSentinel_Project_Report_Short.docx");
const CONTENT_W = 9026; // A4 width minus 1-inch margins, in DXA
const CONTENT_PX = 600;
const ACCENT = "0E7C7B";

// ---------- helpers ----------
const LINE_1_5 = 360; // docx "line" is in 240ths of a line; 1.5 spacing = 360
const p = (text, opts = {}) => new Paragraph({
  spacing: { after: 120, line: LINE_1_5 }, ...opts,
  children: Array.isArray(text) ? text : [new TextRun(text)],
});
const b = (s) => new TextRun({ text: s, bold: true });
const t = (s) => new TextRun(s);
const i = (s) => new TextRun({ text: s, italics: true });
const h1 = (s, pageBreak = false) => new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: pageBreak, children: [new TextRun(s)] });
const h2 = (s) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(s)] });
const bullet = (runs) => new Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 70, line: LINE_1_5 },
  children: typeof runs === "string" ? [new TextRun(runs)] : runs });
const numbered = (runs, ref = "numbers") => new Paragraph({ numbering: { reference: ref, level: 0 }, spacing: { after: 70, line: LINE_1_5 },
  children: typeof runs === "string" ? [new TextRun(runs)] : runs });

function pngSize(file) {
  const buf = fs.readFileSync(file);
  return { w: buf.readUInt32BE(16), h: buf.readUInt32BE(20) };
}
let figNo = 0;
function figure(file, caption, widthFrac = 1.0, size = null) {
  figNo += 1;
  const full = path.join(FIG, file);
  const { w, h } = size || pngSize(full);
  const width = Math.round(CONTENT_PX * widthFrac);
  const height = Math.round(width * h / w);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 100, after: 50 }, keepNext: true,
      children: [new ImageRun({ type: file.endsWith(".jpg") ? "jpg" : "png", data: fs.readFileSync(full),
        transformation: { width, height } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 180 },
      children: [new TextRun({ text: `Figure ${figNo}. `, bold: true, size: 19 }), new TextRun({ text: caption, size: 19, italics: true })] }),
  ];
}
let tabNo = 0;
function tableCaption(text) {
  tabNo += 1;
  return new Paragraph({ spacing: { before: 140, after: 70 }, keepNext: true,
    children: [new TextRun({ text: `Table ${tabNo}. `, bold: true, size: 19 }), new TextRun({ text, size: 19, italics: true })] });
}
const border = { style: BorderStyle.SINGLE, size: 4, color: "B8C2CC" };
const borders = { top: border, bottom: border, left: border, right: border };
function table(headers, rows, fracs) {
  const widths = fracs.map((f) => Math.floor(CONTENT_W * f));
  widths[widths.length - 1] = CONTENT_W - widths.slice(0, -1).reduce((a, c) => a + c, 0);
  const cell = (text, w, header) => new TableCell({
    borders, width: { size: w, type: WidthType.DXA },
    shading: header ? { fill: ACCENT, type: ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 50, bottom: 50, left: 90, right: 90 },
    children: [new Paragraph({ spacing: { after: 0, line: LINE_1_5 },
      children: [new TextRun({ text: String(text), bold: header, color: header ? "FFFFFF" : undefined, size: 18 })] })],
  });
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA }, columnWidths: widths,
    rows: [
      new TableRow({ tableHeader: true, children: headers.map((hd, k) => cell(hd, widths[k], true)) }),
      ...rows.map((r) => new TableRow({ cantSplit: true, children: r.map((c, k) => cell(c, widths[k], false)) })),
    ],
  });
}
const gap = () => new Paragraph({ spacing: { after: 100 }, children: [] });

// ---------- title page ----------
const title = [
  new Paragraph({ spacing: { before: 1800, after: 200 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "IoTSentinel", bold: true, size: 64, color: ACCENT })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 },
    children: [new TextRun({ text: "A Rule-Based Intrusion Detection System for IoT Networks with a Live Monitoring Dashboard", size: 30 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 120 },
    children: [new TextRun({ text: "Project Report", bold: true, size: 28 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 600 },
    children: [new TextRun({ text: "Team No. 2 · IoT Project", size: 24 })] }),
  table(["Reg. No.", "Name", "Department", "Section"], [
    ["145491065", "Sabaresh", "B.Tech AI & DS", "A3"],
    ["145491080", "Sri Pranay J", "B.Tech AI & DS", "A3"],
    ["145491081", "M Steve Anderson", "B.Tech AI & DS", "A3"],
    ["145491163", "Anuraga Sahu", "B.Tech AI & DS", "A3"],
    ["145614128", "Surapureddy Likhitha Sri", "B.E. CSE with CS", "A4"],
  ], [0.2, 0.36, 0.3, 0.14]),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 600, after: 80 },
    children: [new TextRun({ text: "Sathyabama Institute of Science and Technology", size: 24 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "October 2026", size: 22 })] }),
];

const toc = [
  new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, children: [new TextRun("Contents")] }),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
];

// ---------- 1. goal ----------
const ch1 = [
  h1("1. Goal of the project", true),
  p("Smart cameras, plugs, thermostats and door locks often ship with default passwords and open ports, and nothing warns their owner when they are attacked. Home routers pass attack traffic silently, and professional intrusion detection tools are too complex for homes and campuses."),
  p([b("Goal: "), t("build a simple, software-only intrusion detection system (IDS) that detects five common IoT attacks with clear, adjustable rules, shows device status and alerts live, keeps a permanent alert history, and is tested on real traffic so its accuracy is measured, not assumed.")]),
  p("Objectives:"),
  numbered("Simulate six virtual IoT devices and five attacks: flooding, port scan, brute-force login, ARP spoofing and botnet behaviour."),
  numbered("Detect each attack with a threshold over a sliding time window, set in one configuration file."),
  numbered("Show alerts on a live dashboard within five seconds, and store every alert in SQLite."),
  numbered("Measure detection and false alarms, including on the public CIC IoT 2023 dataset."),
  numbered("Reduce alert noise, so one attack gives one incident and harmless events give none."),
  p([b("Out of scope: "), t("live capture from real hardware, automatic blocking, machine learning and cloud deployment. All attack traffic stays inside the laptop.")]),
];

// ---------- 2. requirements ----------
const ch2 = [
  h1("2. Requirements"),
  h2("2.1 Functional requirements"),
  tableCaption("Functional requirements and how each was verified."),
  table(["ID", "The system must", "Verified by"], [
    ["FR-1", "Generate normal traffic for six virtual devices, and five attacks in loud and slow versions", "Unit tests (Figure 8)"],
    ["FR-2", "Drop malformed records", "Malformed-record test"],
    ["FR-3", "Detect each attack with a threshold over a sliding window", "Unit tests, validation report"],
    ["FR-4", "Read all thresholds from rules.yaml, with no code changes", "Threshold sweep (48 settings)"],
    ["FR-5", "Record time, type, source, target and value for every alert", "Alert log (Figure 12)"],
    ["FR-6", "Group repeated alerts into one incident with rising severity", "Grouping test"],
    ["FR-7", "Stay silent on DHCP address changes but alert on ARP spoofing", "3 ARP tests"],
    ["FR-8", "Store every incident in SQLite and show it on a live dashboard", "Demo scenarios A, B, C"],
    ["FR-9", "Replay real packet captures through the same pipeline", "PCAP results (Figure 11)"],
  ], [0.09, 0.62, 0.29]),
  h2("2.2 Non-functional requirements"),
  tableCaption("Non-functional requirements, targets and measured results."),
  table(["ID", "Requirement", "Measured", "Status"], [
    ["NFR-1", "Alert on dashboard within 5 s", "Next refresh (1 s); flood rule fires 0.6 s into the attack", "Met"],
    ["NFR-2", "Over 20,000 records per second", "164,334 to 454,289 records per second", "Met"],
    ["NFR-3", "Catch every loud attack; no false alarms on normal traffic", "5 of 5 caught; 0 false alarms (simulated); 20 per hour on real benign traffic", "Met on simulated"],
    ["NFR-4", "Status never shown by colour alone", "Every device tile says normal or ALERT", "Met"],
    ["NFR-5", "Malformed input never crashes the system", "3,054,980 dataset records, 0 failures", "Met"],
    ["NFR-6", "No alert lost on refresh", "Log intact after page reload", "Met"],
    ["NFR-7", "One laptop, free tools only", "Python, Streamlit, SQLite on Windows 11", "Met"],
    ["NFR-8", "Automated tests run in under 10 s", "18 tests in 0.2 to 2.2 s", "Met"],
  ], [0.1, 0.33, 0.42, 0.15]),
];

// ---------- 3. design ----------
const ch3 = [
  h1("3. Design method"),
  p("The system is a pipeline of small modules connected by one data type, the traffic record. Each module does one job and can be tested alone, and the same pipeline serves the dashboard, the tests and the dataset replay. It was built iteratively: each stage was tested, and what testing found was fed back into the design."),
  h2("3.1 Architecture"),
  ...figure("fig_architecture.png", "Three-layer architecture: traffic sources, processing, output."),
  h2("3.2 Data flow"),
  p("Figure 2 shows how data moves through the system. Records from the three sources pass through the flow collector, which drops malformed ones. Each record is then routed by its event type to the rule that handles it, and every rule's violations feed the incident grouper, which saves incidents to SQLite and updates the dashboard."),
  ...figure("fig_data_flow.png", "Data flow from traffic sources to storage and display."),
  h2("3.3 Detection rules"),
  tableCaption("Detection rules (defaults in rules.yaml)."),
  table(["Attack", "What the rule counts", "Alert when"], [
    ["Flooding", "Packets arriving at one device; blamed on the top sender", "> 500 in 10 s"],
    ["Port scan", "Distinct ports one source opens (connection attempts only)", "> 20 in 10 s"],
    ["Brute force", "Failed logins from one source", "> 5 in 60 s"],
    ["ARP spoofing", "Two MACs claiming one IP inside a 30 s grace window", "Any contention"],
    ["Botnet", "Distinct hosts one device opens telnet connections to", "> 10 in 30 s"],
  ], [0.18, 0.56, 0.26]),
  gap(),
  p([b("Noise controls. "), t("A DHCP address change opens a 30-second grace window instead of an alert; only a second MAC claiming the same IP inside that window counts as spoofing. Repeated alerts with the same rule, source and target within 60 seconds are merged into one incident, whose severity rises at 3, 6 and 10 repeats.")]),
  h2("3.4 Processing flowchart"),
  ...figure("fig_processing_flowchart.png", "What happens to each traffic record.", 0.62),
];

// ---------- 4. implementation ----------
const ch4 = [
  h1("4. Implementation"),
  p("The system is about 840 lines of Python in nine modules; with the validation scripts and tests it is about 1,700 lines."),
  h2("4.1 Modules and their uses"),
  p("The detector itself (src/iotsentinel) is split into nine single-purpose modules, wired together by pipeline.py. A further eight scripts under validation/ build the test data, replay the CIC IoT 2023 dataset, and measure results; they reuse the same modules rather than duplicating logic."),
  tableCaption("Modules in src/iotsentinel and what each one does."),
  table(["Module", "Use"], [
    ["devices.py", "Defines the six virtual IoT devices (camera, plug, thermostat, lock, bulb, assistant) and their IP/MAC addresses."],
    ["device_simulator.py", "Generates normal traffic for the six devices, plus the tricky benign cases (firmware burst, camera stream, DHCP change) used in testing."],
    ["attack_simulator.py", "Generates traffic for the five attacks, each as a loud (obvious) and a slow (under-threshold) variant."],
    ["models.py", "Defines the traffic-record data structure shared by every stage of the pipeline."],
    ["flow_collector.py", "Validates each traffic record and drops malformed ones before they reach the rules."],
    ["rule_engine.py", "The core detector: sliding-window counters for the five rules, the ARP grace-period tracker, and the incident grouper that merges repeats and escalates severity."],
    ["alert_store.py", "Saves and reads incidents from the SQLite database."],
    ["pipeline.py", "Wires the collector, rule engine and alert store together into the single pipeline used by the dashboard, the tests and the dataset replay."],
    ["dashboard.py", "The Streamlit live dashboard: device status tiles, the live traffic chart, the alert log and the attack-launch control panel."],
  ], [0.26, 0.74]),
  tableCaption("Modules in validation/ and what each one does."),
  table(["Module", "Use"], [
    ["scenarios.py", "Builds the labelled test corpus: normal traffic, tricky benign cases, and all five attacks in loud and slow form, each with a known time window."],
    ["metrics.py", "Matches detected incidents against the known time windows and computes precision, recall and false-positive rate."],
    ["run_validation.py", "Runs the test corpus (and, optionally, a CIC IoT 2023 CSV sample) through the pipeline and prints the validation report."],
    ["threshold_sweep.py", "Reruns the test corpus at a range of threshold values and plots detection rate against false alarms."],
    ["cic_loader.py", "Converts a CIC IoT 2023 CSV sample into traffic records that the pipeline can read."],
    ["pcap_loader.py", "Reads a real packet capture (.pcap) and turns its packets into traffic records, with no attack-simulator involvement."],
    ["run_pcap_validation.py", "Runs real packet captures through the pipeline and reports what was detected, missed or falsely alarmed."],
  ], [0.26, 0.74]),
  h2("4.2 Key code"),
  p("The screenshots below show the key parts of the implementation."),
  ...figure("code_rules_yaml.png", "rules.yaml: every threshold lives here, so tuning needs no code changes.", 0.8),
  ...figure("code_rule_engine.png", "Rule engine: each record updates sliding-window counters and is checked against its thresholds.", 0.9),
  ...figure("code_arp_tracker.png", "ARP tracker: a second MAC inside the grace window raises a critical alert.", 0.92),
  ...figure("code_incident_grouper.png", "Incident grouper: repeats are merged and severity escalates.", 0.85),
];

// ---------- 5. testing ----------
const ch5 = [
  h1("5. Verification and testing"),
  p("Testing ran in four layers: unit tests, a labelled simulated test set, real packet captures from CIC IoT 2023, and a live dashboard demo."),
  h2("5.1 Unit tests"),
  p("All 18 automated tests pass. They cover every rule, every noise control, the record validator and the packet-capture reader."),
  ...figure("out_tests.png", "Unit test output.", 0.92),
  h2("5.2 Simulated test set"),
  p("Twenty minutes of normal traffic, with three tricky benign cases (a firmware download burst, a camera stream, a DHCP change), five loud attacks and four slow attacks kept just under the thresholds."),
  ...figure("out_validation.png", "Validation report on the simulated test set.", 0.8),
  p("All five loud attacks were caught and all four slow ones were missed, as expected for fixed thresholds. The only two false alarms came from the flooding rule, triggered by the firmware burst and the camera stream, legitimate traffic that a packet count cannot tell apart from a flood. Grouping turned 13,204 raw violations into 7 incidents. A threshold sweep (Figure 10) confirmed that no single flooding threshold avoids both problems."),
  ...figure("sweep_flooding.png", "Flooding threshold sweep: detection rate (green) against false alarms (red).", 0.62),
  h2("5.3 Real packet captures (CIC IoT 2023)"),
  p("One packet capture per attack category, plus a 23.5-minute benign capture, were read packet by packet and replayed through the pipeline: 344,574 real packets that nobody on the team generated."),
  ...figure("out_pcap.png", "Results on real CIC IoT 2023 packet captures.", 1.0),
  bullet([b("Four of five attacks were detected: "), t("flooding in 0.03 s, ARP spoofing, brute force and port scan.")]),
  bullet([b("Mirai was missed "), t("because CIC's Mirai files contain floods launched by Mirai, while the botnet rule looks for Mirai spreading over telnet.")]),
  bullet([b("Real traffic exposed a flaw in the port-scan rule. "), t("Counting every packet raised 139 false alarms on benign traffic, because server replies go to many random client ports. Counting only connection attempts cut benign false alarms from 147 to 8 (20 per hour), with no attack lost.")]),
  h2("5.4 Live dashboard demo"),
  p("Scenario A: with normal traffic all six devices stayed normal. Scenario B: flooding, port-scan and botnet attacks each turned the right device red within a second, with the attacker named in the log. Scenario C: when an attack ended the device returned to normal and the incident stayed in the log."),
  ...figure("dashboard_alert.jpg", "Live dashboard during a flood on camera-1.", 0.9, { w: 800, h: 562 }),
  h2("5.5 Defects found by testing"),
  tableCaption("Main defects found and fixed."),
  table(["Defect", "Found by", "Fix"], [
    ["Port-scan rule counted server replies (139 false alarms)", "Real packet test", "Count connection attempts only"],
    ["Dashboard rebuilt attacks every second, so scans were never detected", "Live demo", "Generate once, release over time"],
    ["Distinct-port counter slowed to 12,341 records/s during floods", "Performance test", "Running counts: 181,783 records/s"],
    ["Overlapping test attacks made a slow attack look detected", "First validation run", "Space attacks apart"],
    ["Device's own traffic was blamed as a second flooder", "Code review of tests", "Blame the top sender"],
  ], [0.5, 0.2, 0.3]),
];

// ---------- 6-7 ----------
const ch6 = [
  h1("6. Lessons learned"),
  bullet([b("Self-generated traffic flatters the detector. "), t("Every rule looked perfect on our own traffic; real packets produced 147 false alarms in 23.5 minutes. Real data belongs in testing from the start.")]),
  bullet([b("Define exactly what a rule counts. "), t("\"Ports contacted by one source\" did not say whether replies count, and that gap caused 94% of the real false alarms.")]),
  bullet([b("Noise reduction matters as much as detection. "), t("Grouping turned 13,204 alerts into 7 incidents; nobody reads thousands of alerts.")]),
  bullet([b("Thresholds are trade-offs. "), t("No flooding threshold separates slow floods from big downloads; comparing each device with its own normal traffic would.")]),
  bullet([b("Test the test harness. "), t("Several defects were in our own test and demo code, and they hid or inflated results.")]),
  h1("7. Conclusion"),
  p("IoTSentinel meets its goal. It detects five IoT attacks with adjustable rules, shows them live, stores every incident, and its accuracy has been measured on real traffic: four of five attack categories detected, with 20 false alarms per hour after fixing the flaw real traffic exposed. Its limits are fixed thresholds, which miss slow attacks, and brute-force detection that relies on connection counts. Per-device baselines and live capture are the natural next steps. It is a proof of concept, not a replacement for professional security tools."),
  h1("References"),
  numbered("Neto, E. C. P. et al. (2023). CICIoT2023: A real-time dataset and benchmark for large-scale attacks in IoT environment. Sensors, 23(13), 5941.", "refs"),
  numbered("Canadian Institute for Cybersecurity. CIC IoT Dataset 2023. https://www.unb.ca/cic/datasets/iotdataset-2023.html", "refs"),
  numbered("OWASP Foundation. OWASP Internet of Things Project. https://owasp.org/www-project-internet-of-things/", "refs"),
  numbered("Streamlit Documentation. https://docs.streamlit.io/", "refs"),
];

// ---------- document ----------
const listLevel = (fmt, text) => ({ level: 0, format: fmt, text, alignment: AlignmentType.LEFT,
  style: { paragraph: { indent: { left: 540, hanging: 360 } } } });
const page = { size: { width: 11906, height: 16838 }, margin: { top: 1300, bottom: 1300, left: 1440, right: 1440 } };
const doc = new Document({
  creator: "Team No. 2",
  title: "IoTSentinel Project Report",
  styles: {
    default: { document: { run: { font: "Arial", size: 24 },
      paragraph: { spacing: { line: LINE_1_5, lineRule: "auto" } } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 32, bold: true, color: ACCENT }, paragraph: { spacing: { before: 360, after: 160, line: LINE_1_5 }, outlineLevel: 0, keepNext: true } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 25, bold: true, color: "1F2933" }, paragraph: { spacing: { before: 220, after: 100, line: LINE_1_5 }, outlineLevel: 1, keepNext: true } },
    ],
  },
  numbering: { config: [
    { reference: "bullets", levels: [listLevel(LevelFormat.BULLET, "•")] },
    { reference: "numbers", levels: [listLevel(LevelFormat.DECIMAL, "%1.")] },
    { reference: "refs", levels: [listLevel(LevelFormat.DECIMAL, "[%1]")] },
  ] },
  sections: [
    { properties: { page }, children: title },
    { properties: { page: { ...page, pageNumbers: { start: 1 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER,
        children: [new TextRun({ text: "IoTSentinel project report  ·  ", size: 18, color: "7B8794" }),
          new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "7B8794" })] })] }) },
      children: [...toc, ...ch1, ...ch2, ...ch3, ...ch4, ...ch5, ...ch6] },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(OUT, buf);
  console.log("wrote", OUT, `(${figNo} figures, ${tabNo} tables)`);
});

