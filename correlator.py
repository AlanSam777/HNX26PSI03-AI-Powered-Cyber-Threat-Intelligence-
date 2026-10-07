import pandas as pd


# ==========================================================
# CONFIGURATION
# ==========================================================

CORRELATION_WINDOW_MINUTES = 60
MIN_EVIDENCE_SIGNALS = 3


# ==========================================================
# LOAD DATA
# ==========================================================

df = pd.read_csv("scored_logs.csv")

df["timestamp"] = pd.to_datetime(
    df["timestamp"]
)

anomalies = df[
    df["is_anomaly"] == 1
].copy()


# ==========================================================
# OUTPUT CONTAINERS
# ==========================================================

incidents = []
incident_events = []
relationships = []
mitre_mappings = []
suppressed_cases = []
remediation_recommendations = []

incident_counter = 1


# ==========================================================
# HELPER - VALID VALUE
# ==========================================================

def value_present(value):

    if pd.isna(value):
        return False

    text = str(value).strip()

    return (
        text != ""
        and
        text.lower()
        not in {
            "nan",
            "none",
            "null"
        }
    )


# ==========================================================
# TEMPORAL WINDOWING
# ==========================================================

def split_into_windows(
    group,
    window_minutes
):

    group = (
        group
        .sort_values("timestamp")
        .reset_index(drop=True)
    )

    if group.empty:
        return []

    windows = []

    current_rows = [
        group.iloc[0]
    ]

    window_start = (
        group.iloc[0]["timestamp"]
    )

    for index in range(
        1,
        len(group)
    ):

        row = group.iloc[index]

        elapsed = (
            row["timestamp"]
            -
            window_start
        ).total_seconds() / 60

        if elapsed <= window_minutes:

            current_rows.append(
                row
            )

        else:

            windows.append(
                pd.DataFrame(
                    current_rows
                )
            )

            current_rows = [
                row
            ]

            window_start = (
                row["timestamp"]
            )

    windows.append(
        pd.DataFrame(
            current_rows
        )
    )

    return windows


# ==========================================================
# EVIDENCE ENGINE
# ==========================================================

def calculate_evidence(group):

    suspicious_login = (

        (
            group["event_type"]
            == "LOGIN"
        )

        &

        (
            (group["new_device"] == 1)
            |
            (group["new_ip"] == 1)
        )

    ).any()


    sensitive_access = (
        group["sensitive_file"]
        == 1
    ).any()


    suspicious_application = (
        group["suspicious_app"]
        == 1
    ).any()


    usb_activity = (
        group["usb_activity"]
        == 1
    ).any()


    potential_exfiltration = (

        group["event_type"].isin(
            [
                "FILE_COPY_USB",
                "UPLOAD_EXTERNAL"
            ]
        )

        |

        (
            group["large_transfer"]
            == 1
        )

    ).any()


    return {

        "Suspicious Login":
            bool(suspicious_login),

        "Sensitive Data Access":
            bool(sensitive_access),

        "Suspicious Application":
            bool(suspicious_application),

        "USB Activity":
            bool(usb_activity),

        "Potential Exfiltration":
            bool(potential_exfiltration)
    }


# ==========================================================
# MITRE ATT&CK SEMANTIC MAPPING
# ==========================================================

def get_mitre_mapping(row):

    mappings = []

    event_type = str(
        row.get(
            "event_type",
            ""
        )
    )

    application = str(
        row.get(
            "application",
            ""
        )
    ).lower()

    destination = str(
        row.get(
            "destination",
            ""
        )
    ).lower()


    # ------------------------------------------------------
    # VALID ACCOUNTS CONTEXT
    # ------------------------------------------------------

    if (
        event_type == "LOGIN"
        and
        (
            row.get(
                "new_device",
                0
            ) == 1
            or
            row.get(
                "new_ip",
                0
            ) == 1
        )
    ):

        mappings.append({

            "technique_id":
                "T1078",

            "technique_name":
                "Valid Accounts",

            "tactic":
                "Multiple",

            "confidence":
                "Contextual",

            "evidence_basis":
                (
                    "Login from an unseen device or IP is "
                    "consistent with Valid Accounts behaviour. "
                    "Credential compromise is not independently proven."
                )
        })


    # ------------------------------------------------------
    # POWERSHELL
    # ------------------------------------------------------

    if (
        event_type == "APP_ACCESS"
        and
        application == "powershell"
    ):

        mappings.append({

            "technique_id":
                "T1059.001",

            "technique_name":
                "Command and Scripting Interpreter: PowerShell",

            "tactic":
                "Execution",

            "confidence":
                "Contextual",

            "evidence_basis":
                (
                    "PowerShell activity was observed inside "
                    "the correlated attack window."
                )
        })


    # ------------------------------------------------------
    # LOCAL DATA COLLECTION
    # ------------------------------------------------------

    if (
        event_type == "FILE_ACCESS"
        and
        row.get(
            "sensitive_file",
            0
        ) == 1
    ):

        mappings.append({

            "technique_id":
                "T1005",

            "technique_name":
                "Data from Local System",

            "tactic":
                "Collection",

            "confidence":
                "Contextual",

            "evidence_basis":
                (
                    "Sensitive local data was accessed "
                    "during the reconstructed sequence."
                )
        })


    # ------------------------------------------------------
    # USB EXFILTRATION
    # ------------------------------------------------------

    if event_type == "FILE_COPY_USB":

        mappings.append({

            "technique_id":
                "T1052.001",

            "technique_name":
                (
                    "Exfiltration Over Physical Medium: "
                    "Exfiltration over USB"
                ),

            "tactic":
                "Exfiltration",

            "confidence":
                "High",

            "evidence_basis":
                (
                    "A file copy to removable USB media "
                    "was directly recorded."
                )
        })


    # ------------------------------------------------------
    # CLOUD / EXTERNAL EXFILTRATION
    # ------------------------------------------------------

    if event_type == "UPLOAD_EXTERNAL":

        if (
            "cloud" in destination
            or
            "drive" in destination
            or
            "dropbox" in destination
        ):

            mappings.append({

                "technique_id":
                    "T1567.002",

                "technique_name":
                    (
                        "Exfiltration Over Web Service: "
                        "Exfiltration to Cloud Storage"
                    ),

                "tactic":
                    "Exfiltration",

                "confidence":
                    "High",

                "evidence_basis":
                    (
                        "A file upload to an external "
                        "cloud-storage destination was recorded."
                    )
            })

        else:

            mappings.append({

                "technique_id":
                    "T1567",

                "technique_name":
                    "Exfiltration Over Web Service",

                "tactic":
                    "Exfiltration",

                "confidence":
                    "Contextual",

                "evidence_basis":
                    (
                        "An upload to an external service "
                        "was recorded."
                    )
            })


    return mappings


# ==========================================================
# RESPONSE RECOMMENDATION ENGINE
# ==========================================================
#
# IMPORTANT:
# These are analyst recommendations.
# ChainSight does NOT automatically execute containment.
# ==========================================================

def generate_remediation(
    incident_id,
    user,
    group,
    evidence
):

    recommendations = []


    def add(
        priority,
        category,
        recommendation,
        rationale
    ):

        recommendations.append({

            "incident_id":
                incident_id,

            "priority":
                priority,

            "category":
                category,

            "recommendation":
                recommendation,

            "rationale":
                rationale
        })


    # ------------------------------------------------------
    # UNIVERSAL EVIDENCE PRESERVATION
    # ------------------------------------------------------

    add(
        "HIGH",
        "Evidence Preservation",
        (
            "Preserve relevant endpoint, authentication "
            "and network telemetry before remediation."
        ),
        (
            "Maintains evidence required for investigation "
            "and root-cause analysis."
        )
    )


    # ------------------------------------------------------
    # SUSPICIOUS LOGIN
    # ------------------------------------------------------

    if evidence[
        "Suspicious Login"
    ]:

        add(
            "HIGH",
            "Identity",
            (
                f"Review active sessions for {user} "
                "and terminate suspicious sessions."
            ),
            (
                "The account was observed from a previously "
                "unseen device or IP address."
            )
        )

        add(
            "MEDIUM",
            "Identity",
            (
                f"Review authentication history for {user} "
                "and validate whether the activity was authorized."
            ),
            (
                "Helps distinguish account misuse from "
                "legitimate remote access."
            )
        )


    # ------------------------------------------------------
    # SENSITIVE DATA ACCESS
    # ------------------------------------------------------

    if evidence[
        "Sensitive Data Access"
    ]:

        add(
            "HIGH",
            "Data Protection",
            (
                "Review all sensitive files accessed during "
                "the incident time window."
            ),
            (
                "Sensitive resources were accessed as part "
                "of the reconstructed chain."
            )
        )


    # ------------------------------------------------------
    # SUSPICIOUS APPLICATION
    # ------------------------------------------------------

    if evidence[
        "Suspicious Application"
    ]:

        add(
            "HIGH",
            "Endpoint Investigation",
            (
                "Investigate suspicious application activity "
                "and collect associated process or command history."
            ),
            (
                "Potentially dual-use administrative tooling "
                "appeared inside the correlated attack sequence."
            )
        )


    # ------------------------------------------------------
    # USB ACTIVITY
    # ------------------------------------------------------

    if evidence[
        "USB Activity"
    ]:

        add(
            "HIGH",
            "Removable Media",
            (
                "Identify and quarantine the removable device "
                "for forensic review where organizational policy permits."
            ),
            (
                "USB activity was linked to the reconstructed incident."
            )
        )


    # ------------------------------------------------------
    # USB EXFILTRATION
    # ------------------------------------------------------

    if (
        group["event_type"]
        == "FILE_COPY_USB"
    ).any():

        add(
            "CRITICAL",
            "Containment",
            (
                "Isolate the affected endpoint from the network "
                "pending analyst validation."
            ),
            (
                "Sensitive data transfer to removable media "
                "was directly observed."
            )
        )

        add(
            "HIGH",
            "Forensics",
            (
                "Determine whether additional files were copied "
                "to the same removable device."
            ),
            (
                "Establishes the potential scope of data exposure."
            )
        )


    # ------------------------------------------------------
    # EXTERNAL UPLOAD
    # ------------------------------------------------------

    if (
        group["event_type"]
        == "UPLOAD_EXTERNAL"
    ).any():

        add(
            "CRITICAL",
            "Containment",
            (
                "Contain the affected endpoint and investigate "
                "the external destination."
            ),
            (
                "An outbound transfer of sensitive data "
                "was directly observed."
            )
        )

        add(
            "HIGH",
            "Network Security",
            (
                "Consider blocking the external destination "
                "after validating business impact."
            ),
            (
                "Reduces the possibility of continued "
                "unauthorized outbound transfer."
            )
        )


    # ------------------------------------------------------
    # POTENTIAL EXFILTRATION
    # ------------------------------------------------------

    if evidence[
        "Potential Exfiltration"
    ]:

        add(
            "HIGH",
            "Incident Response",
            (
                "Escalate the incident for data-exposure "
                "assessment and determine the affected information."
            ),
            (
                "The evidence chain contains indicators "
                "consistent with data exfiltration."
            )
        )


    return recommendations


# ==========================================================
# PROCESS USERS
# ==========================================================

for user, user_group in anomalies.groupby(
    "user"
):

    windows = split_into_windows(
        user_group,
        CORRELATION_WINDOW_MINUTES
    )


    for window_number, group in enumerate(
        windows,
        start=1
    ):

        group = (
            group
            .sort_values(
                "timestamp"
            )
        )


        # ==================================================
        # EVIDENCE
        # ==================================================

        evidence = calculate_evidence(
            group
        )

        evidence_count = sum(
            evidence.values()
        )

        evidence_total = len(
            evidence
        )

        evidence_completeness = (
            evidence_count
            /
            evidence_total
        )


        start_time = (
            group["timestamp"]
            .min()
        )

        end_time = (
            group["timestamp"]
            .max()
        )

        duration_minutes = (
            end_time
            -
            start_time
        ).total_seconds() / 60


        # ==================================================
        # INCIDENT
        # ==================================================

        if (
            evidence_count
            >=
            MIN_EVIDENCE_SIGNALS
        ):

            incident_id = (
                f"INC-{incident_counter:03d}"
            )


            severity = (
                "CRITICAL"
                if evidence_count >= 4
                else "HIGH"
            )


            max_anomaly_score = (
                group[
                    "anomaly_score"
                ]
                .max()
            )


            risk_score = round(
                (
                    0.60
                    *
                    max_anomaly_score
                )
                +
                (
                    0.40
                    *
                    evidence_completeness
                ),
                4
            )


            risk_score_percent = round(
                risk_score
                *
                100
            )


            incidents.append({

                "incident_id":
                    incident_id,

                "user":
                    user,

                "start_time":
                    start_time,

                "end_time":
                    end_time,

                "duration_minutes":
                    round(
                        duration_minutes,
                        2
                    ),

                "event_count":
                    len(group),

                "evidence_count":
                    evidence_count,

                "evidence_total":
                    evidence_total,

                "evidence_completeness":
                    round(
                        evidence_completeness,
                        3
                    ),

                "correlation_window_minutes":
                    CORRELATION_WINDOW_MINUTES,

                "risk_score":
                    risk_score_percent,

                "severity":
                    severity,

                "suspicious_login":
                    int(
                        evidence[
                            "Suspicious Login"
                        ]
                    ),

                "sensitive_data_access":
                    int(
                        evidence[
                            "Sensitive Data Access"
                        ]
                    ),

                "suspicious_application":
                    int(
                        evidence[
                            "Suspicious Application"
                        ]
                    ),

                "usb_activity":
                    int(
                        evidence[
                            "USB Activity"
                        ]
                    ),

                "potential_exfiltration":
                    int(
                        evidence[
                            "Potential Exfiltration"
                        ]
                    )
            })


            # ==============================================
            # REMEDIATION
            # ==============================================

            remediation_recommendations.extend(
                generate_remediation(
                    incident_id,
                    user,
                    group,
                    evidence
                )
            )


            # ==============================================
            # PROCESS EVENTS
            # ==============================================

            for _, row in group.iterrows():

                event = (
                    row.to_dict()
                )

                event[
                    "incident_id"
                ] = incident_id

                incident_events.append(
                    event
                )


                # ==========================================
                # MITRE
                # ==========================================

                for mapping in get_mitre_mapping(
                    row
                ):

                    mitre_mappings.append({

                        "incident_id":
                            incident_id,

                        "event_id":
                            row.get(
                                "event_id",
                                ""
                            ),

                        "timestamp":
                            row[
                                "timestamp"
                            ],

                        "user":
                            user,

                        "event_type":
                            row[
                                "event_type"
                            ],

                        **mapping
                    })


                # ==========================================
                # IP -> USER
                # ==========================================

                if value_present(
                    row.get(
                        "source_ip"
                    )
                ):

                    relationships.append({

                        "incident_id":
                            incident_id,

                        "source":
                            row[
                                "source_ip"
                            ],

                        "source_type":
                            "IP",

                        "relationship":
                            "CONNECTED_TO",

                        "destination":
                            user,

                        "destination_type":
                            "User"
                    })


                # ==========================================
                # USER -> DEVICE
                # ==========================================

                if value_present(
                    row.get(
                        "device"
                    )
                ):

                    relationships.append({

                        "incident_id":
                            incident_id,

                        "source":
                            user,

                        "source_type":
                            "User",

                        "relationship":
                            "USED_DEVICE",

                        "destination":
                            row[
                                "device"
                            ],

                        "destination_type":
                            "Device"
                    })


                # ==========================================
                # DEVICE -> FILE
                # ==========================================

                if (
                    row[
                        "event_type"
                    ]
                    in {
                        "FILE_ACCESS",
                        "FILE_COPY_USB",
                        "UPLOAD_EXTERNAL"
                    }

                    and

                    value_present(
                        row.get(
                            "resource"
                        )
                    )
                ):

                    relationships.append({

                        "incident_id":
                            incident_id,

                        "source":
                            row[
                                "device"
                            ],

                        "source_type":
                            "Device",

                        "relationship":
                            row[
                                "event_type"
                            ],

                        "destination":
                            row[
                                "resource"
                            ],

                        "destination_type":
                            "File"
                    })


                # ==========================================
                # DEVICE -> APPLICATION
                # ==========================================

                if (
                    row[
                        "event_type"
                    ]
                    == "APP_ACCESS"

                    and

                    value_present(
                        row.get(
                            "application"
                        )
                    )
                ):

                    relationships.append({

                        "incident_id":
                            incident_id,

                        "source":
                            row[
                                "device"
                            ],

                        "source_type":
                            "Device",

                        "relationship":
                            "USED_APPLICATION",

                        "destination":
                            row[
                                "application"
                            ],

                        "destination_type":
                            "Application"
                    })


                # ==========================================
                # FILE -> USB
                # ==========================================

                if (
                    row[
                        "event_type"
                    ]
                    == "FILE_COPY_USB"

                    and

                    value_present(
                        row.get(
                            "usb_id"
                        )
                    )
                ):

                    relationships.append({

                        "incident_id":
                            incident_id,

                        "source":
                            row[
                                "resource"
                            ],

                        "source_type":
                            "File",

                        "relationship":
                            "COPIED_TO",

                        "destination":
                            row[
                                "usb_id"
                            ],

                        "destination_type":
                            "USB"
                    })


                # ==========================================
                # FILE -> EXTERNAL DESTINATION
                # ==========================================

                if (
                    row[
                        "event_type"
                    ]
                    == "UPLOAD_EXTERNAL"

                    and

                    value_present(
                        row.get(
                            "destination"
                        )
                    )
                ):

                    relationships.append({

                        "incident_id":
                            incident_id,

                        "source":
                            row[
                                "resource"
                            ],

                        "source_type":
                            "File",

                        "relationship":
                            "UPLOADED_TO",

                        "destination":
                            row[
                                "destination"
                            ],

                        "destination_type":
                            "External Service"
                    })


            # ==============================================
            # OUTPUT
            # ==============================================

            print()

            print("=" * 70)

            print(
                "INCIDENT DETECTED:",
                incident_id
            )

            print(
                "User:",
                user
            )

            print(
                "Duration:",
                round(
                    duration_minutes,
                    2
                ),
                "minutes"
            )

            print(
                "Evidence:",
                f"{evidence_count}/{evidence_total}"
            )

            print(
                "Evidence completeness:",
                f"{evidence_completeness * 100:.0f}%"
            )

            print(
                "Risk score:",
                f"{risk_score_percent}/100"
            )

            print(
                "Severity:",
                severity
            )


            for name, present in evidence.items():

                symbol = (
                    "+"
                    if present
                    else "-"
                )

                print(
                    f"  {symbol} {name}"
                )


            incident_counter += 1


        # ==================================================
        # SUPPRESSION
        # ==================================================

        else:

            suppressed_cases.append({

                "user":
                    user,

                "window_number":
                    window_number,

                "start_time":
                    start_time,

                "end_time":
                    end_time,

                "duration_minutes":
                    round(
                        duration_minutes,
                        2
                    ),

                "event_count":
                    len(group),

                "evidence_count":
                    evidence_count,

                "evidence_total":
                    evidence_total,

                "evidence_completeness":
                    round(
                        evidence_completeness,
                        3
                    ),

                "correlation_window_minutes":
                    CORRELATION_WINDOW_MINUTES,

                "decision":
                    "SUPPRESSED",

                "decision_reason":
                    (
                        "Insufficient correlated "
                        "attack evidence"
                    )
            })


            print()

            print(
                "SUPPRESSED:",
                user
            )

            print(
                "Evidence:",
                f"{evidence_count}/{evidence_total}"
            )


# ==========================================================
# DATAFRAMES
# ==========================================================

incident_df = pd.DataFrame(
    incidents
)

incident_event_df = pd.DataFrame(
    incident_events
)

relationship_df = pd.DataFrame(
    relationships
)

mitre_df = pd.DataFrame(
    mitre_mappings
)

suppressed_df = pd.DataFrame(
    suppressed_cases
)

remediation_df = pd.DataFrame(
    remediation_recommendations
)


# ==========================================================
# DEDUPLICATE
# ==========================================================

if not relationship_df.empty:

    relationship_df = (
        relationship_df
        .drop_duplicates()
        .reset_index(drop=True)
    )


if not mitre_df.empty:

    mitre_df = (
        mitre_df
        .drop_duplicates()
        .reset_index(drop=True)
    )


if not remediation_df.empty:

    remediation_df = (
        remediation_df
        .drop_duplicates()
        .reset_index(drop=True)
    )


# ==========================================================
# SAVE OUTPUTS
# ==========================================================

incident_df.to_csv(
    "incidents.csv",
    index=False
)

incident_event_df.to_csv(
    "incident_events.csv",
    index=False
)

relationship_df.to_csv(
    "relationships.csv",
    index=False
)

mitre_df.to_csv(
    "mitre_mapping.csv",
    index=False
)

suppressed_df.to_csv(
    "suppressed_cases.csv",
    index=False
)

remediation_df.to_csv(
    "remediation_recommendations.csv",
    index=False
)


# ==========================================================
# INCIDENT LEVEL EVALUATION
# ==========================================================

true_attack_scenarios = set(
    df[
        df["ground_truth"]
        == 1
    ]["scenario"]
)


detected_attack_scenarios = set()

true_confirmed_incidents = 0
false_confirmed_incidents = 0


if not incident_event_df.empty:

    for incident_id, group in (
        incident_event_df.groupby(
            "incident_id"
        )
    ):

        contains_attack = (
            group["ground_truth"]
            == 1
        ).any()


        if contains_attack:

            true_confirmed_incidents += 1

            detected_attack_scenarios.update(
                group[
                    group["ground_truth"]
                    == 1
                ]["scenario"]
                .unique()
            )

        else:

            false_confirmed_incidents += 1


missed_attack_scenarios = (
    true_attack_scenarios
    -
    detected_attack_scenarios
)


incident_precision = (

    true_confirmed_incidents
    /
    (
        true_confirmed_incidents
        +
        false_confirmed_incidents
    )

    if (
        true_confirmed_incidents
        +
        false_confirmed_incidents
    ) > 0

    else 0
)


incident_recall = (

    len(
        detected_attack_scenarios
    )
    /
    len(
        true_attack_scenarios
    )

    if len(
        true_attack_scenarios
    ) > 0

    else 0
)


incident_f1 = (

    2
    *
    incident_precision
    *
    incident_recall
    /
    (
        incident_precision
        +
        incident_recall
    )

    if (
        incident_precision
        +
        incident_recall
    ) > 0

    else 0
)


evaluation_df = pd.DataFrame(
    [
        {
            "metric":
                "True Attack Scenarios",
            "value":
                len(
                    true_attack_scenarios
                )
        },

        {
            "metric":
                "Reconstructed Attack Scenarios",
            "value":
                len(
                    detected_attack_scenarios
                )
        },

        {
            "metric":
                "True Confirmed Incidents",
            "value":
                true_confirmed_incidents
        },

        {
            "metric":
                "False Confirmed Incidents",
            "value":
                false_confirmed_incidents
        },

        {
            "metric":
                "Missed Attack Scenarios",
            "value":
                len(
                    missed_attack_scenarios
                )
        },

        {
            "metric":
                "Incident Precision",
            "value":
                round(
                    incident_precision,
                    3
                )
        },

        {
            "metric":
                "Incident Recall",
            "value":
                round(
                    incident_recall,
                    3
                )
        },

        {
            "metric":
                "Incident F1",
            "value":
                round(
                    incident_f1,
                    3
                )
        }
    ]
)


evaluation_df.to_csv(
    "incident_evaluation.csv",
    index=False
)


# ==========================================================
# FINAL OUTPUT
# ==========================================================

print()

print("=" * 70)
print("CORRELATION FINISHED")
print("=" * 70)

print(
    "Temporal correlation window:",
    CORRELATION_WINDOW_MINUTES,
    "minutes"
)

print(
    "Confirmed incidents:",
    len(
        incident_df
    )
)

print(
    "Incident events:",
    len(
        incident_event_df
    )
)

print(
    "Suppressed cases:",
    len(
        suppressed_df
    )
)

print(
    "Entity relationships:",
    len(
        relationship_df
    )
)

print(
    "MITRE mappings:",
    len(
        mitre_df
    )
)

print(
    "Response recommendations:",
    len(
        remediation_df
    )
)


print()

print("=" * 70)
print("INCIDENT-LEVEL EVALUATION")
print("=" * 70)

print(
    "True attack scenarios:",
    len(
        true_attack_scenarios
    )
)

print(
    "Reconstructed attack scenarios:",
    len(
        detected_attack_scenarios
    )
)

print(
    "True confirmed incidents:",
    true_confirmed_incidents
)

print(
    "False confirmed incidents:",
    false_confirmed_incidents
)

print(
    "Missed scenarios:",
    len(
        missed_attack_scenarios
    )
)

print()

print(
    "Incident Precision:",
    round(
        incident_precision,
        3
    )
)

print(
    "Incident Recall:",
    round(
        incident_recall,
        3
    )
)

print(
    "Incident F1:",
    round(
        incident_f1,
        3
    )
)

print("=" * 70)