# forensic_parser.py
import os
import re
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import plotly.express as px
from datetime import datetime
from fpdf import FPDF

# === Suspicious Binaries ===
suspicious_binaries = ["/bin/xz", "/bin/nc", "/usr/bin/python3", "/usr/bin/perl"]

# --- Log Parsing Function ---
def parse_logs_from_directory(logdir):
    pattern = re.compile(
        r'(?P<log_id>0x[0-9a-fA-F]+)\[ts:(?P<timestamp>\d+)\]\|EVNT:(?P<event_type>[^!]+)!@'
        r'(?P<action>[^_]+)_(?P<actor_type>[^:]+):(?P<actor>[^=]+)=*>(?P<target>.+)'
    )

    entries = []
    for fname in os.listdir(logdir):
        if fname.endswith(".vlog"):
            with open(os.path.join(logdir, fname), 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = pattern.match(line.strip())
                    if match:
                        data = match.groupdict()
                        data['timestamp'] = int(data['timestamp'])
                        data['file'] = fname
                        data['datetime'] = datetime.fromtimestamp(data['timestamp'])
                        entries.append(data)

    return pd.DataFrame(entries)

# --- Summary Output ---
def print_summary(df):
    print("\n📊 Summary Report:")
    print(f"- Total log entries: {len(df)}")
    unique_users = df['actor'].dropna().unique()
    print(f"- Unique users: {len(unique_users)} ({', '.join(unique_users)})")
    print("- Top 5 Actions:")
    print(df['action'].value_counts().head())

# --- Timeline Chart ---
def generate_timeline(df):
    df['action_type'] = df['action'].copy()
    action_counts = df['action'].value_counts()
    df['action_type'] = df['action'].apply(lambda x: x if action_counts[x] <= 3 else 'COMMON')

    df.set_index('datetime').groupby('action_type').resample('1Min').size().unstack(fill_value=0).plot(
        kind='bar', stacked=True, figsize=(12, 6))
    plt.title("Event Frequency Over Time")
    plt.xlabel("Time")
    plt.ylabel("Event Count")
    plt.tight_layout()
    plt.savefig("action_frequency.png")
    print("✅ Timeline saved as action_frequency.png")

# --- Custom Anomaly Detection Rules ---
def custom_anomaly_detection(df):
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    df.sort_values(by='datetime', inplace=True)

    anomalies = []
    grouped = df.groupby('actor')

    for user, logs in grouped:
        logs = logs.sort_values(by='datetime').reset_index(drop=True)
        for i, row in logs.iterrows():
            current_action = row['action']
            current_line = row.to_dict()
            curr_time = row['datetime']
            log_text = f"{row['event_type']}!@{row['action']}_{row['actor_type']}:{row['actor']}=>{row['target']}"

            # Rule 1: Shadow Load followed by Delete
            if "SHD" in current_action:
                for j in range(i+1, min(i+6, len(logs))):
                    if "DEL" in logs.loc[j, 'action']:
                        if (logs.loc[j, 'datetime'] - curr_time).total_seconds() <= 600:
                            anomalies.append({
                                "timestamp": logs.loc[j, 'datetime'].strftime("%Y-%m-%d %H:%M:%S"),
                                "user": user,
                                "reason": "Shadow load followed by process delete",
                                "details": f"{log_text} → {logs.loc[j, 'target']}",
                                "ip_address": "N/A",
                                "action_type": "Delete",
                                "severity": "High",
                                "log_source": logs.loc[j, 'file']
                            })

            # Rule 2: Create followed by Delete of same file
            if "CRE" in current_action:
                created_path = row['target']
                for j in range(i+1, min(i+6, len(logs))):
                    if "DEL" in logs.loc[j, 'action'] and created_path in logs.loc[j, 'target']:
                        anomalies.append({
                            "timestamp": logs.loc[j, 'datetime'].strftime("%Y-%m-%d %H:%M:%S"),
                            "user": user,
                            "reason": "Created then deleted same file",
                            "details": f"{log_text} → {logs.loc[j, 'target']}",
                            "ip_address": "N/A",
                            "action_type": "Delete",
                            "severity": "Medium",
                            "log_source": logs.loc[j, 'file']
                        })

            # Rule 3: Suspicious binary executed
            if "RUN" in current_action:
                if any(b in row['target'] for b in suspicious_binaries):
                    anomalies.append({
                        "timestamp": curr_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "user": user,
                        "reason": f"Suspicious binary executed",
                        "details": log_text,
                        "ip_address": "N/A",
                        "action_type": "Execute",
                        "severity": "High",
                        "log_source": row['file']
                    })

            # Rule 4: Deleted a suspicious binary
            if "DEL" in current_action:
                path = row['target']
                if path.endswith(('.exe', '.bin', '.out', '.so')) or any(p in path for p in ['/bin/', '/tmp/', '/sbin/', '/usr/local/bin/']):
                    anomalies.append({
                        "timestamp": curr_time.strftime("%Y-%m-%d %H:%M:%S"),
                        "user": user,
                        "reason": "Deleted binary/suspicious executable file",
                        "details": log_text,
                        "ip_address": "N/A",
                        "action_type": "Delete",
                        "severity": "High",
                        "log_source": row['file']
                    })

    anomalies_df = pd.DataFrame(anomalies)
    if not anomalies_df.empty:
        # Generate a clean styled HTML table for anomalies
        styled_html = anomalies_df.head(100).to_html(classes="styled-table", index=False)

        with open("anomalies.html", "w", encoding="utf-8") as f:
            f.write(f"""
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <title>Anomaly Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            padding: 40px;
            color: #333;
        }}
        h1 {{
            color: #444;
        }}
        .styled-table {{
            border-collapse: collapse;
            width: 100%;
            font-size: 14px;
        }}
        .styled-table th, .styled-table td {{
            border: 1px solid #ccc;
            padding: 10px;
            text-align: left;
        }}
        .styled-table th {{
            background-color: #eaeaea;
        }}
        .styled-table tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
    </style>
</head>
<body>
    <h1>Anomaly Report</h1>
    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    {styled_html}
</body>
</html>
""")
        print("✅ Anomaly table saved as anomalies.html")
    else:
        print("⚠️ No anomalies detected.")

    return anomalies_df

# --- PDF Report Generator ---
def generate_pdf_report(df, anomalies):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Forensic Log Analysis Report", ln=True, align="C")
    pdf.ln(10)
    pdf.cell(200, 10, txt=f"Total log entries: {len(df)}", ln=True)
    pdf.cell(200, 10, txt=f"Unique users: {df['actor'].nunique()} ({', '.join(df['actor'].unique())})", ln=True)
    pdf.ln(5)
    pdf.cell(200, 10, txt="Top 5 Actions:", ln=True)
    for action, count in df['action'].value_counts().head().items():
        pdf.cell(200, 10, txt=f"{action}: {count}", ln=True)
    pdf.ln(10)

    if os.path.exists("action_frequency.png"):
        pdf.image("action_frequency.png", x=10, w=180)
        pdf.ln(10)

    if not anomalies.empty:
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(45, 10, "Timestamp", 1)
        pdf.cell(25, 10, "User", 1)
        pdf.cell(25, 10, "Action", 1)
        pdf.cell(25, 10, "Severity", 1)
        pdf.cell(70, 10, "Reason", 1)
        pdf.ln()
        pdf.set_font("Arial", size=10)

        for i, row in anomalies.head(10).iterrows():
            pdf.cell(45, 10, row['timestamp'], 1)
            pdf.cell(25, 10, row['user'], 1)
            pdf.cell(25, 10, row['action_type'], 1)
            pdf.cell(25, 10, row['severity'], 1)
            reason_text = row['reason'][:60] + ('...' if len(row['reason']) > 60 else '')
            pdf.cell(70, 10, reason_text, 1)
            pdf.ln()
    else:
        pdf.cell(200, 10, txt="No anomalies detected.", ln=True)

    pdf.output("report.pdf")
    print("📄 PDF report saved as report.pdf")
    print("📄 PDF report saved as report.pdf")

# --- Main CLI Handler ---
def main():
    parser = argparse.ArgumentParser(description="Forensic Log Parser")
    parser.add_argument("logdir", help="Directory containing .vlog files")
    parser.add_argument("--summary", action="store_true", help="Print summary report")
    parser.add_argument("--timeline", action="store_true", help="Generate timeline chart")
    parser.add_argument("--alerts", action="store_true", help="Run anomaly detection and report")
    parser.add_argument("--pdf", action="store_true", help="Generate PDF report")
    args = parser.parse_args()

    if not os.path.isdir(args.logdir):
        print("❌ Error: Invalid log directory")
        return

    df = parse_logs_from_directory(args.logdir)

    if args.summary:
        print_summary(df)

    if args.timeline:
        generate_timeline(df)

    anomalies = pd.DataFrame()
    if args.alerts:
        anomalies = custom_anomaly_detection(df)

    if args.pdf:
        generate_pdf_report(df, anomalies)

if __name__ == "__main__":
    main()
