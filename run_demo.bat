@echo off
cd /d "%~dp0"
cmake -S . -B build || exit /b 1
cmake --build build --config Release || exit /b 1
if exist build\Release\loginguard.exe (set EXE=build\Release\loginguard.exe) else (set EXE=build\loginguard.exe)
%EXE% run --logs data\sample_logs.csv --db loginguard.db
