@echo off
cd /d "%~dp0"
rem --server.address localhost keeps the dashboard reachable from this
rem machine only; remove it to let others on the same network open it.
".venv\Scripts\python.exe" -m streamlit run src\iotsentinel\dashboard.py --server.address localhost --server.headless true
pause
