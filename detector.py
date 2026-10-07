import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest


# ==========================================================
# CONFIGURATION
# ==========================================================

BASELINE_SPLIT_NAME = "baseline"

LARGE_TRANSFER_THRESHOLD = 10_000_000

AI_BASELINE_PERCENTILE = 0.99

CONTEXT_THRESHOLD = 0.15


# ==========================================================
# SECURITY POLICY KNOWLEDGE
# ==========================================================
#
# IMPORTANT:
# User devices, IP addresses, applications and normal hours
# are NOT hardcoded.
#
# Only security-policy concepts are configured here.
# ==========================================================

SENSITIVE_FILES = {
    "payroll.xlsx",
    "employee_credentials.csv",
    "salary.xlsx",
    "customer_database.csv"
}

SUSPICIOUS_APPS = {
    "powershell",
    "cmd.exe",
    "python.exe",
    "wmic.exe"
}


# ==========================================================
# LOAD NORMALIZED DATA
# ==========================================================

df = pd.read_csv(
    "normalized_logs.csv"
)

df["timestamp"] = pd.to_datetime(
    df["timestamp"],
    errors="coerce"
)

df = df[
    df["timestamp"].notna()
].copy()


# ==========================================================
# CLEAN NUMERIC VALUES
# ==========================================================

df["bytes_transferred"] = pd.to_numeric(
    df["bytes_transferred"],
    errors="coerce"
).fillna(0)

df["ground_truth"] = pd.to_numeric(
    df["ground_truth"],
    errors="coerce"
).fillna(0).astype(int)


# ==========================================================
# CLEAN TEXT VALUES
# ==========================================================

text_columns = [
    "event_id",
    "log_source",
    "user",
    "device",
    "source_ip",
    "event_type",
    "application",
    "resource",
    "usb_id",
    "destination",
    "scenario",
    "dataset_split"
]

for column in text_columns:

    if column not in df.columns:
        df[column] = ""

    df[column] = (
        df[column]
        .fillna("")
        .astype(str)
    )


# ==========================================================
# BASIC TEMPORAL FEATURES
# ==========================================================

df["hour"] = (
    df["timestamp"]
    .dt.hour
)


# ==========================================================
# BASELINE REFERENCE DATA
# ==========================================================

baseline_reference = df[
    df["dataset_split"]
    == BASELINE_SPLIT_NAME
].copy()


if baseline_reference.empty:

    raise RuntimeError(
        "No baseline events found. "
        "Cannot learn behavioural baselines."
    )


# ==========================================================
# LEARN NORMAL DEVICES
# ==========================================================

learned_devices = (
    baseline_reference[
        baseline_reference["device"] != ""
    ]
    .groupby("user")["device"]
    .apply(set)
    .to_dict()
)


# ==========================================================
# LEARN NORMAL IPS
# ==========================================================

learned_ips = (
    baseline_reference[
        baseline_reference["source_ip"] != ""
    ]
    .groupby("user")["source_ip"]
    .apply(set)
    .to_dict()
)


# ==========================================================
# LEARN NORMAL APPLICATIONS
# ==========================================================

learned_apps = (
    baseline_reference[
        baseline_reference["application"] != ""
    ]
    .groupby("user")["application"]
    .apply(
        lambda values: {
            str(value).lower()
            for value in values
        }
    )
    .to_dict()
)


# ==========================================================
# LEARN NORMAL ACTIVITY HOURS
# ==========================================================

user_hour_baselines = (
    baseline_reference
    .groupby("user")["hour"]
    .agg(
        [
            "min",
            "max",
            "mean",
            "std"
        ]
    )
    .to_dict(
        orient="index"
    )
)


# ==========================================================
# NEW DEVICE
# ==========================================================

def detect_new_device(row):

    device = row["device"]

    if device == "":
        return 0

    known = learned_devices.get(
        row["user"],
        set()
    )

    return int(
        device not in known
    )


df["new_device"] = df.apply(
    detect_new_device,
    axis=1
)


# ==========================================================
# NEW IP
# ==========================================================

def detect_new_ip(row):

    source_ip = row["source_ip"]

    if source_ip == "":
        return 0

    known = learned_ips.get(
        row["user"],
        set()
    )

    return int(
        source_ip not in known
    )


df["new_ip"] = df.apply(
    detect_new_ip,
    axis=1
)


# ==========================================================
# NEW APPLICATION
# ==========================================================

def detect_new_application(row):

    application = str(
        row["application"]
    ).lower()

    if application == "":
        return 0

    known = learned_apps.get(
        row["user"],
        set()
    )

    return int(
        application not in known
    )


df["new_application"] = df.apply(
    detect_new_application,
    axis=1
)


# ==========================================================
# DYNAMIC UNUSUAL TIME
# ==========================================================

def detect_unusual_time(row):

    baseline_info = (
        user_hour_baselines.get(
            row["user"]
        )
    )

    if baseline_info is None:
        return 1

    hour = row["hour"]

    return int(
        hour < baseline_info["min"]
        or
        hour > baseline_info["max"]
    )


df["unusual_time"] = df.apply(
    detect_unusual_time,
    axis=1
)


# ==========================================================
# SENSITIVE FILE
# ==========================================================

sensitive_lower = {
    item.lower()
    for item in SENSITIVE_FILES
}

df["sensitive_file"] = (
    df["resource"]
    .str.lower()
    .isin(
        sensitive_lower
    )
    .astype(int)
)


# ==========================================================
# USB ACTIVITY
# ==========================================================

df["usb_activity"] = (
    df["event_type"]
    .isin(
        [
            "USB_INSERT",
            "FILE_COPY_USB"
        ]
    )
    .astype(int)
)


# ==========================================================
# EXTERNAL UPLOAD
# ==========================================================

df["external_upload"] = (
    df["event_type"]
    .eq(
        "UPLOAD_EXTERNAL"
    )
    .astype(int)
)


# ==========================================================
# SUSPICIOUS APPLICATION
# ==========================================================

df["suspicious_app"] = (
    df["application"]
    .str.lower()
    .isin(
        SUSPICIOUS_APPS
    )
    .astype(int)
)


# ==========================================================
# LARGE TRANSFER
# ==========================================================

df["large_transfer"] = (
    df["bytes_transferred"]
    >
    LARGE_TRANSFER_THRESHOLD
).astype(int)


# ==========================================================
# LOG TRANSFER FEATURE
# ==========================================================

df["log_bytes"] = np.log1p(
    df["bytes_transferred"]
)


# ==========================================================
# FINAL ML TRAINING BASELINE
# ==========================================================

baseline = df[
    df["dataset_split"]
    == BASELINE_SPLIT_NAME
].copy()


# ==========================================================
# ISOLATION FOREST
# ==========================================================

ai_features = [
    "hour",
    "log_bytes"
]


X_train = baseline[
    ai_features
].copy()


model = IsolationForest(
    n_estimators=200,
    contamination="auto",
    random_state=42
)

model.fit(
    X_train
)


# ==========================================================
# AI SCORING
# ==========================================================

X_all = df[
    ai_features
].copy()


df["ai_raw_score"] = (
    -model.score_samples(
        X_all
    )
)


baseline_scores = (
    -model.score_samples(
        X_train
    )
)


ai_threshold = np.quantile(
    baseline_scores,
    AI_BASELINE_PERCENTILE
)


df["ai_outlier"] = (
    df["ai_raw_score"]
    >
    ai_threshold
).astype(int)


# ==========================================================
# NORMALIZED AI SCORE
# ==========================================================

score_min = (
    df["ai_raw_score"]
    .min()
)

score_max = (
    df["ai_raw_score"]
    .max()
)


if score_max > score_min:

    df["ai_score"] = (
        df["ai_raw_score"]
        -
        score_min
    ) / (
        score_max
        -
        score_min
    )

else:

    df["ai_score"] = 0.0


# ==========================================================
# CONTEXT SCORE
# ==========================================================
#
# IMPORTANT FIX:
#
# unusual_time = 0.15
#
# Therefore Hari's isolated late login remains an anomaly
# but is later SUPPRESSED by the evidence gate.
#
# That is exactly the behaviour ChainSight is intended to
# demonstrate.
# ==========================================================

df["context_score"] = (

    df["new_device"] * 0.20

    +

    df["new_ip"] * 0.20

    +

    df["unusual_time"] * 0.15

    +

    df["sensitive_file"] * 0.18

    +

    df["usb_activity"] * 0.18

    +

    df["external_upload"] * 0.22

    +

    df["suspicious_app"] * 0.18

    +

    df["large_transfer"] * 0.18

    +

    df["new_application"] * 0.08
)


df["context_score"] = (
    df["context_score"]
    .clip(
        upper=1.0
    )
)


# ==========================================================
# HYBRID SCORE
# ==========================================================

df["anomaly_score"] = (

    df["ai_score"] * 0.35

    +

    df["context_score"] * 0.65
)


# ==========================================================
# SECURITY-RELEVANT EVENT TYPES
# ==========================================================

security_relevant_events = {
    "LOGIN",
    "FILE_ACCESS",
    "APP_ACCESS",
    "USB_INSERT",
    "FILE_COPY_USB",
    "UPLOAD_EXTERNAL"
}


# ==========================================================
# FINAL ANOMALY DECISION
# ==========================================================

df["is_anomaly"] = (

    (
        df["context_score"]
        >=
        CONTEXT_THRESHOLD
    )

    |

    (
        (df["ai_outlier"] == 1)

        &

        df["event_type"].isin(
            security_relevant_events
        )
    )

).astype(int)


# ==========================================================
# EXPLANATION ENGINE
# ==========================================================

def generate_reason(row):

    reasons = []

    if row["new_device"]:
        reasons.append(
            "Previously unseen device"
        )

    if row["new_ip"]:
        reasons.append(
            "Previously unseen IP"
        )

    if row["unusual_time"]:
        reasons.append(
            "Outside learned activity hours"
        )

    if row["new_application"]:
        reasons.append(
            "Application not seen in baseline"
        )

    if row["sensitive_file"]:
        reasons.append(
            "Sensitive file"
        )

    if row["usb_activity"]:
        reasons.append(
            "USB activity"
        )

    if row["suspicious_app"]:
        reasons.append(
            "Suspicious application"
        )

    if row["external_upload"]:
        reasons.append(
            "External upload"
        )

    if row["large_transfer"]:
        reasons.append(
            "Large transfer"
        )

    if row["ai_outlier"]:
        reasons.append(
            "AI behavioural outlier"
        )

    if not reasons:
        return "Normal behaviour"

    return " | ".join(
        reasons
    )


df["anomaly_reason"] = df.apply(
    generate_reason,
    axis=1
)


# ==========================================================
# SAVE LEARNED BASELINES
# ==========================================================

baseline_summary = []


for user in sorted(
    baseline_reference["user"].unique()
):

    hour_info = (
        user_hour_baselines.get(
            user,
            {}
        )
    )

    baseline_summary.append({

        "user":
            user,

        "known_devices":
            ", ".join(
                sorted(
                    learned_devices.get(
                        user,
                        set()
                    )
                )
            ),

        "known_ips":
            ", ".join(
                sorted(
                    learned_ips.get(
                        user,
                        set()
                    )
                )
            ),

        "known_applications":
            ", ".join(
                sorted(
                    learned_apps.get(
                        user,
                        set()
                    )
                )
            ),

        "normal_hour_min":
            hour_info.get(
                "min",
                ""
            ),

        "normal_hour_max":
            hour_info.get(
                "max",
                ""
            ),

        "average_activity_hour":
            round(
                hour_info.get(
                    "mean",
                    0
                ),
                2
            )
    })


baseline_summary_df = pd.DataFrame(
    baseline_summary
)


baseline_summary_df.to_csv(
    "learned_baselines.csv",
    index=False
)


# ==========================================================
# SAVE SCORED LOGS
# ==========================================================

df.to_csv(
    "scored_logs.csv",
    index=False
)


# ==========================================================
# EVENT-LEVEL EVALUATION
# ==========================================================

true_attack = (
    df["ground_truth"]
    == 1
)

predicted = (
    df["is_anomaly"]
    == 1
)


tp = int(
    (
        true_attack
        &
        predicted
    ).sum()
)

fp = int(
    (
        ~true_attack
        &
        predicted
    ).sum()
)

fn = int(
    (
        true_attack
        &
        ~predicted
    ).sum()
)

tn = int(
    (
        ~true_attack
        &
        ~predicted
    ).sum()
)


precision = (
    tp / (tp + fp)
    if tp + fp > 0
    else 0
)

recall = (
    tp / (tp + fn)
    if tp + fn > 0
    else 0
)

f1 = (
    (
        2 * precision * recall
    )
    /
    (
        precision + recall
    )
    if precision + recall > 0
    else 0
)

fpr = (
    fp / (fp + tn)
    if fp + tn > 0
    else 0
)


# ==========================================================
# TERMINAL OUTPUT
# ==========================================================

print("=" * 80)
print("CHAINSIGHT DYNAMIC BASELINE DETECTOR")
print("=" * 80)

print(
    "Input events:",
    len(df)
)

print(
    "Users with learned baselines:",
    len(
        learned_devices
    )
)

print(
    "Log sources:",
    df["log_source"].nunique()
)

print(
    "AI threshold:",
    round(
        ai_threshold,
        4
    )
)

print(
    "Detected anomalies:",
    int(
        df["is_anomaly"].sum()
    )
)

print()


anomalies = df[
    df["is_anomaly"]
    == 1
].sort_values(
    "anomaly_score",
    ascending=False
)


print(
    anomalies[
        [
            "timestamp",
            "log_source",
            "user",
            "event_type",
            "device",
            "source_ip",
            "resource",
            "application",
            "anomaly_score",
            "anomaly_reason",
            "scenario"
        ]
    ].to_string(
        index=False
    )
)


print()

print("=" * 80)
print("EVENT-LEVEL EVALUATION")
print("=" * 80)

print(
    "True Positives :",
    tp
)

print(
    "False Positives:",
    fp
)

print(
    "False Negatives:",
    fn
)

print(
    "True Negatives :",
    tn
)

print()

print(
    "Precision:",
    round(
        precision,
        3
    )
)

print(
    "Recall:",
    round(
        recall,
        3
    )
)

print(
    "F1:",
    round(
        f1,
        3
    )
)

print(
    "False Positive Rate:",
    round(
        fpr,
        4
    )
)

print("=" * 80)

print(
    "Learned baseline file:",
    "learned_baselines.csv"
)

print("=" * 80)