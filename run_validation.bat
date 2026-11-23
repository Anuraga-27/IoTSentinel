@echo off
cd /d "%~dp0"
set PY=".venv\Scripts\python.exe"
echo === Tests ===
%PY% -m unittest discover -s tests
echo.
echo === Validation report ===
%PY% validation\run_validation.py
echo.
echo === Validation report with CIC IoT 2023 samples (D:\CIC) ===
if exist D:\CIC\BenignTraffic.sample.csv %PY% validation\run_validation.py --cic-csv D:\CIC\BenignTraffic.sample.csv --cic-csv D:\CIC\DDoS-TCP_Flood.sample.csv --cic-csv D:\CIC\Recon-PortScan.sample.csv --cic-csv D:\CIC\DictionaryBruteForce.sample.csv --cic-csv D:\CIC\MITM-ArpSpoofing.sample.csv --cic-csv D:\CIC\Mirai-greeth_flood.sample.csv
echo.
echo === Real packet captures from CIC IoT 2023 (D:\CIC\pcap) ===
if exist D:\CIC\pcap %PY% validation\run_pcap_validation.py D:\CIC\pcap
echo.
echo === Threshold sweep (plots in validation\out) ===
%PY% validation\threshold_sweep.py
echo.
echo === Throughput benchmark ===
%PY% validation\benchmark.py
pause
