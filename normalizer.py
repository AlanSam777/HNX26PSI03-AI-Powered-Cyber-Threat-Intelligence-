import pandas as pd


# ==========================================================
# INPUT FILES
# ==========================================================

INPUT_FILES = {
    "AUTHENTICATION": "authentication_logs.csv",
    "FILE": "file_logs.csv",
    "DEVICE": "device_logs.csv",
    "APPLICATION": "application_logs.csv",
    "NETWORK": "network_logs.csv"
}


# ==========================================================
# COMMON NORMALIZED SCHEMA
# ==========================================================

NORMALIZED_COLUMNS = [
    "event_id",
    "timestamp",
    "log_source",
    "user",
    "device",
    "source_ip",
    "event_type",
    "application",
    "resource",
    "usb_id",
    "destination",
    "bytes_transferred",
    "ground_truth",
    "scenario",
    "dataset_split"
]


# ==========================================================
# LOAD + NORMALIZE ONE SOURCE
# ==========================================================

def normalize_source(source_name, file_name):

    df = pd.read_csv(file_name)

    # Add source identifier
    df["log_source"] = source_name

    # ------------------------------------------------------
    # ENSURE ALL NORMALIZED FIELDS EXIST
    # ------------------------------------------------------

    defaults = {
        "event_id": "",
        "timestamp": "",
        "user": "",
        "device": "",
        "source_ip": "",
        "event_type": "",
        "application": "",
        "resource": "",
        "usb_id": "",
        "destination": "",
        "bytes_transferred": 0,
        "ground_truth": 0,
        "scenario": "UNKNOWN",
        "dataset_split": "unknown"
    }

    for column, default_value in defaults.items():

        if column not in df.columns:
            df[column] = default_value


    # ------------------------------------------------------
    # CLEAN NUMERIC FIELDS
    # ------------------------------------------------------

    df["bytes_transferred"] = pd.to_numeric(
        df["bytes_transferred"],
        errors="coerce"
    ).fillna(0)

    df["ground_truth"] = pd.to_numeric(
        df["ground_truth"],
        errors="coerce"
    ).fillna(0).astype(int)


    # ------------------------------------------------------
    # CLEAN TEXT FIELDS
    # ------------------------------------------------------

    text_columns = [
        "event_id",
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

        df[column] = (
            df[column]
            .fillna("")
            .astype(str)
        )


    # ------------------------------------------------------
    # TIMESTAMP
    # ------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )


    # Drop broken timestamps
    df = df[
        df["timestamp"].notna()
    ].copy()


    # ------------------------------------------------------
    # OUTPUT ONLY NORMALIZED SCHEMA
    # ------------------------------------------------------

    return df[
        NORMALIZED_COLUMNS
    ]


# ==========================================================
# NORMALIZE ALL SOURCES
# ==========================================================

normalized_frames = []

print("=" * 70)
print("CHAINSIGHT LOG NORMALIZATION")
print("=" * 70)

for source_name, file_name in INPUT_FILES.items():

    try:

        source_df = normalize_source(
            source_name,
            file_name
        )

        normalized_frames.append(
            source_df
        )

        print(
            f"{source_name:<15} -> "
            f"{len(source_df)} events normalized"
        )

    except FileNotFoundError:

        print(
            f"{source_name:<15} -> "
            f"FILE NOT FOUND: {file_name}"
        )


# ==========================================================
# MERGE ALL NORMALIZED SOURCES
# ==========================================================

if not normalized_frames:

    raise RuntimeError(
        "No log sources were loaded."
    )


normalized = pd.concat(
    normalized_frames,
    ignore_index=True
)


# ==========================================================
# REMOVE DUPLICATES
# ==========================================================
#
# Important because some events can legitimately appear
# in multiple source files.
#
# Example:
# UPLOAD_EXTERNAL may appear in both file_logs and
# network_logs.
#
# event_id is used as the common event identity.
# ==========================================================

before_dedup = len(
    normalized
)

normalized = normalized.drop_duplicates(
    subset=["event_id"],
    keep="first"
)

after_dedup = len(
    normalized
)

duplicates_removed = (
    before_dedup
    -
    after_dedup
)


# ==========================================================
# SORT CHRONOLOGICALLY
# ==========================================================

normalized = normalized.sort_values(
    "timestamp"
).reset_index(
    drop=True
)


# ==========================================================
# SAVE NORMALIZED DATA
# ==========================================================

normalized.to_csv(
    "normalized_logs.csv",
    index=False
)


# ==========================================================
# SUMMARY
# ==========================================================

print()
print("=" * 70)
print("NORMALIZATION COMPLETED")
print("=" * 70)

print(
    "Events before deduplication:",
    before_dedup
)

print(
    "Duplicates removed:",
    duplicates_removed
)

print(
    "Final normalized events:",
    after_dedup
)

print()

print("Events by source:")

print(
    normalized[
        "log_source"
    ].value_counts()
)

print()

print(
    "Output file: normalized_logs.csv"
)

print("=" * 70)