@echo off
for /F "tokens=*" %%a in (pip_requirements.txt) do (
    pip uninstall -y %%a
)