# 🕵️‍♂️ Forensic Log Analyzer (CLI Tool)

This project is a lightweight command-line tool built in Python to help parse, understand, and investigate custom `.vlog` session logs. It was designed with a forensic mindset — to reverse engineer unknown log formats, extract key data, organize events into a timeline, and detect unusual or suspicious behavior.

## What It Does

- Parses `.vlog` files and structures the raw logs into clean, readable formats.
- Handles broken or incomplete log lines without crashing.
- Classifies log entries by type: user activity, file operations, processes, network/IP connections.
- Builds a timestamp-based timeline of all events.
- Detects basic anomalies using rule-based logic (e.g., unusual user actions, repeated IP behavior).
- Generates summary reports and optional visualizations (charts, dashboards).
- Works from the command line and accepts an entire folder of logs.

---

## How to Run

Place your `.vlog` files in a folder in directory of the python code file and run :

```bash
python3 forensic_parser.py <path_to_log_folder> --summary --timeline --alerts --visualize
