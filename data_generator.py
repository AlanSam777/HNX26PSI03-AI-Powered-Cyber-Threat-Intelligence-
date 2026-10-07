import pandas as pd
import random
from datetime import datetime, timedelta

random.seed(42)

# ==========================================================
# CONFIGURATION
# ==========================================================

START_TIME = datetime(2026, 10, 7, 8, 0)

users = [
    "Alan",
    "Hari",
    "Alishiba",
    "Praisy",
    "Sam",
    "George",
    "Angel",
    "Jenifa"
]

devices = {
    "Alan": "PC-101",
    "Hari": "PC-102",
    "Alishiba": "PC-103",
    "Praisy": "PC-104",
    "Sam": "PC-105",
    "George": "PC-106",
    "Angel": "PC-107",
    "Jenifa": "PC-108"
}

normal_ips = {
    "Alan": "10.0.0.11",
    "Hari": "10.0.0.12",
    "Alishiba": "10.0.0.13",
    "Praisy": "10.0.0.14",
    "Sam": "10.0.0.15",
    "George": "10.0.0.16",
    "Angel": "10.0.0.17",
    "Jenifa": "10.0.0.18"
}

normal_files = [
    "meeting_notes.docx",
    "weekly_report.xlsx",
    "project_plan.pdf",
    "presentation.pptx",
    "attendance.xlsx",
    "policy.pdf",
    "task_list.txt"
]

normal_apps = [
    "Chrome",
    "Outlook",
    "Teams",
    "Word",
    "Excel"
]

rows = []

event_id = 1


# ==========================================================
# HELPER FUNCTION
# ==========================================================

def add_event(
    timestamp,
    user,
    event_type,
    device=None,
    source_ip=None,
    resource="",
    usb_id="",
    application="",
    destination="",
    bytes_transferred=0,
    ground_truth=0,
    scenario="NORMAL",
    dataset_split="baseline"
):

    global event_id

    rows.append({
        "event_id": f"EVT-{event_id:05d}",
        "timestamp": timestamp,
        "user": user,
        "device": device if device else devices[user],
        "source_ip": source_ip if source_ip else normal_ips[user],
        "event_type": event_type,
        "resource": resource,
        "usb_id": usb_id,
        "application": application,
        "destination": destination,
        "bytes_transferred": bytes_transferred,
        "ground_truth": ground_truth,
        "scenario": scenario,
        "dataset_split": dataset_split
    })

    event_id += 1


# ==========================================================
# NORMAL ENTERPRISE ACTIVITY
# ==========================================================

for _ in range(800):

    user = random.choice(users)

    # normal working hours
    hour = random.randint(8, 18)
    minute = random.randint(0, 59)

    timestamp = START_TIME.replace(
        hour=hour,
        minute=minute
    )

    event_type = random.choice([
        "LOGIN",
        "FILE_ACCESS",
        "APP_ACCESS"
    ])

    if event_type == "LOGIN":

        add_event(
            timestamp,
            user,
            "LOGIN"
        )

    elif event_type == "FILE_ACCESS":

        add_event(
            timestamp,
            user,
            "FILE_ACCESS",
            resource=random.choice(normal_files)
        )

    elif event_type == "APP_ACCESS":

        add_event(
            timestamp,
            user,
            "APP_ACCESS",
            application=random.choice(normal_apps)
        )


# ==========================================================
# NORMAL NETWORK ACTIVITY
# ==========================================================

for _ in range(100):

    user = random.choice(users)

    timestamp = START_TIME + timedelta(
        minutes=random.randint(0, 600)
    )

    add_event(
        timestamp,
        user,
        "NETWORK_CONNECTION",
        destination=random.choice([
            "office365.com",
            "google.com",
            "teams.microsoft.com",
            "github.com"
        ]),
        bytes_transferred=random.randint(
            1000,
            500000
        )
    )


# ==========================================================
# BENIGN ANOMALY 1
# HARI LATE LOGIN
# ==========================================================

add_event(
    datetime(2026, 10, 7, 22, 10),
    "Hari",
    "LOGIN",
    scenario="BENIGN_LATE_LOGIN",
    dataset_split="evaluation"
)


# ==========================================================
# BENIGN ANOMALY 2
# GEORGE CONNECTS USB BUT DOES NOTHING MALICIOUS
# ==========================================================

add_event(
    datetime(2026, 10, 7, 17, 20),
    "George",
    "USB_INSERT",
    usb_id="USB-GEORGE-01",
    scenario="BENIGN_USB",
    dataset_split="evaluation"
)


# ==========================================================
# THREAT 1
# ALAN — USB DATA EXFILTRATION
# ==========================================================

# suspicious login

add_event(
    datetime(2026, 10, 7, 21, 43),
    "Alan",
    "LOGIN",
    device="UNKNOWN-LAPTOP-01",
    source_ip="185.44.21.90",
    ground_truth=1,
    scenario="USB_EXFILTRATION",
    dataset_split="evaluation"
)

# sensitive file access

add_event(
    datetime(2026, 10, 7, 21, 46),
    "Alan",
    "FILE_ACCESS",
    device="UNKNOWN-LAPTOP-01",
    source_ip="185.44.21.90",
    resource="payroll.xlsx",
    ground_truth=1,
    scenario="USB_EXFILTRATION",
    dataset_split="evaluation"
)

# USB insertion

add_event(
    datetime(2026, 10, 7, 21, 49),
    "Alan",
    "USB_INSERT",
    device="UNKNOWN-LAPTOP-01",
    source_ip="185.44.21.90",
    usb_id="USB-991",
    ground_truth=1,
    scenario="USB_EXFILTRATION",
    dataset_split="evaluation"
)

# file copy

add_event(
    datetime(2026, 10, 7, 21, 51),
    "Alan",
    "FILE_COPY_USB",
    device="UNKNOWN-LAPTOP-01",
    source_ip="185.44.21.90",
    resource="payroll.xlsx",
    usb_id="USB-991",
    bytes_transferred=25000000,
    ground_truth=1,
    scenario="USB_EXFILTRATION",
    dataset_split="evaluation"
)


# ==========================================================
# THREAT 2
# JENIFA — CLOUD DATA EXFILTRATION
# ==========================================================

# suspicious external login

add_event(
    datetime(2026, 10, 7, 20, 15),
    "Jenifa",
    "LOGIN",
    device="UNKNOWN-LAPTOP-77",
    source_ip="91.205.189.15",
    ground_truth=1,
    scenario="CLOUD_EXFILTRATION",
    dataset_split="evaluation"
)

# suspicious PowerShell usage

add_event(
    datetime(2026, 10, 7, 20, 18),
    "Jenifa",
    "APP_ACCESS",
    device="UNKNOWN-LAPTOP-77",
    source_ip="91.205.189.15",
    application="PowerShell",
    ground_truth=1,
    scenario="CLOUD_EXFILTRATION",
    dataset_split="evaluation"
)

# confidential file accessed

add_event(
    datetime(2026, 10, 7, 20, 21),
    "Jenifa",
    "FILE_ACCESS",
    device="UNKNOWN-LAPTOP-77",
    source_ip="91.205.189.15",
    resource="employee_credentials.csv",
    ground_truth=1,
    scenario="CLOUD_EXFILTRATION",
    dataset_split="evaluation"
)

# external upload

add_event(
    datetime(2026, 10, 7, 20, 24),
    "Jenifa",
    "UPLOAD_EXTERNAL",
    device="UNKNOWN-LAPTOP-77",
    source_ip="91.205.189.15",
    resource="employee_credentials.csv",
    destination="external-cloud-storage",
    bytes_transferred=18000000,
    ground_truth=1,
    scenario="CLOUD_EXFILTRATION",
    dataset_split="evaluation"
)


# ==========================================================
# DATAFRAME
# ==========================================================

df = pd.DataFrame(rows)

df["timestamp"] = pd.to_datetime(
    df["timestamp"]
)

df = df.sort_values(
    "timestamp"
).reset_index(drop=True)


# ==========================================================
# SAVE NORMALIZED DATA
# ==========================================================

df.to_csv(
    "all_logs.csv",
    index=False
)


# ==========================================================
# CREATE MULTIPLE LOG SOURCES
# ==========================================================

authentication_logs = df[
    df["event_type"] == "LOGIN"
]

file_logs = df[
    df["event_type"].isin([
        "FILE_ACCESS",
        "FILE_COPY_USB",
        "UPLOAD_EXTERNAL"
    ])
]

device_logs = df[
    df["event_type"] == "USB_INSERT"
]

application_logs = df[
    df["event_type"] == "APP_ACCESS"
]

network_logs = df[
    df["event_type"].isin([
        "NETWORK_CONNECTION",
        "UPLOAD_EXTERNAL"
    ])
]


authentication_logs.to_csv(
    "authentication_logs.csv",
    index=False
)

file_logs.to_csv(
    "file_logs.csv",
    index=False
)

device_logs.to_csv(
    "device_logs.csv",
    index=False
)

application_logs.to_csv(
    "application_logs.csv",
    index=False
)

network_logs.to_csv(
    "network_logs.csv",
    index=False
)


# ==========================================================
# OUTPUT
# ==========================================================

print("=" * 60)

print("CHAINSIGHT DATASET GENERATED")

print("=" * 60)

print("Total events:", len(df))

print("Users:", len(users))

print()

print("Authentication logs:", len(authentication_logs))

print("File logs:", len(file_logs))

print("Device logs:", len(device_logs))

print("Application logs:", len(application_logs))

print("Network logs:", len(network_logs))

print()

print("Threat scenarios:")

print("1. Alan   -> USB Data Exfiltration")

print("2. Jenifa -> Cloud Data Exfiltration")

print()

print("Benign anomaly scenarios:")

print("1. Hari   -> Late Login")

print("2. George -> USB Insert Only")

print("=" * 60)