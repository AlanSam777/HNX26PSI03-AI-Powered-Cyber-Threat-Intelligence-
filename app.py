import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import html


# ==========================================================
# PAGE CONFIG
# ==========================================================

st.set_page_config(
    page_title="ChainSight AI",
    page_icon="🛡️",
    layout="wide"
)


# ==========================================================
# LOAD CSV
# ==========================================================

def load_csv(
    filename,
    required=True
):

    try:

        return pd.read_csv(
            filename
        )

    except FileNotFoundError:

        if required:

            st.error(
                f"Required file missing: {filename}"
            )

            st.stop()

        return pd.DataFrame()


logs = load_csv(
    "scored_logs.csv"
)

incidents = load_csv(
    "incidents.csv"
)

incident_events = load_csv(
    "incident_events.csv"
)

relationships = load_csv(
    "relationships.csv"
)

mitre = load_csv(
    "mitre_mapping.csv",
    required=False
)

baselines = load_csv(
    "learned_baselines.csv",
    required=False
)

incident_evaluation = load_csv(
    "incident_evaluation.csv",
    required=False
)

suppressed_cases = load_csv(
    "suppressed_cases.csv",
    required=False
)

remediation = load_csv(
    "remediation_recommendations.csv",
    required=False
)


# ==========================================================
# TIMESTAMPS
# ==========================================================

logs["timestamp"] = pd.to_datetime(
    logs["timestamp"],
    errors="coerce"
)

incident_events["timestamp"] = pd.to_datetime(
    incident_events["timestamp"],
    errors="coerce"
)


if (
    not mitre.empty
    and
    "timestamp" in mitre.columns
):

    mitre["timestamp"] = pd.to_datetime(
        mitre["timestamp"],
        errors="coerce"
    )


# ==========================================================
# HEADER
# ==========================================================

st.title(
    "🛡️ ChainSight AI"
)

st.subheader(
    "Evidence-Driven Multi-Stage Attack Reconstruction"
)

st.caption(
    "Multi-source normalization • learned behavioural baselines • "
    "hybrid anomaly detection • temporal correlation • evidence gating • "
    "MITRE ATT&CK context • response recommendations • incident reporting"
)

st.divider()


# ==========================================================
# GLOBAL METRICS
# ==========================================================

total_events = len(
    logs
)

total_anomalies = int(
    logs["is_anomaly"].sum()
)

confirmed_incidents = len(
    incidents
)

incident_event_count = len(
    incident_events
)

suppressed_anomalous_events = max(
    0,
    total_anomalies
    -
    incident_event_count
)


c1, c2, c3, c4 = st.columns(
    4
)

c1.metric(
    "Total Events",
    total_events
)

c2.metric(
    "Anomalous Events",
    total_anomalies
)

c3.metric(
    "Confirmed Incidents",
    confirmed_incidents
)

c4.metric(
    "Suppressed Anomalous Events",
    suppressed_anomalous_events
)

st.divider()


# ==========================================================
# EVENT LEVEL METRICS
# ==========================================================

true_attack = (
    logs["ground_truth"]
    == 1
)

predicted = (
    logs["is_anomaly"]
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
    if tp + fp
    else 0
)

recall = (
    tp / (tp + fn)
    if tp + fn
    else 0
)

f1 = (
    2 * precision * recall /
    (precision + recall)
    if precision + recall
    else 0
)

fpr = (
    fp / (fp + tn)
    if fp + tn
    else 0
)


# ==========================================================
# INCIDENT IDS
# ==========================================================

incident_ids = sorted(
    incidents[
        "incident_id"
    ]
    .astype(str)
    .unique()
    .tolist()
)


# ==========================================================
# SAFE DISPLAY VALUE
# ==========================================================

def safe_value(
    row,
    column
):

    if column not in row.index:
        return "N/A"

    value = row[
        column
    ]

    if pd.isna(
        value
    ):
        return "N/A"

    text = str(
        value
    ).strip()

    if text.lower() in {
        "",
        "nan",
        "none",
        "null"
    }:
        return "N/A"

    return value


# ==========================================================
# MAIN TABS
# ==========================================================

(
    tab1,
    tab2,
    tab3,
    tab4,
    tab5,
    tab6
) = st.tabs(
    [
        "🚨 Incident Investigation",
        "✅ False-Positive Suppression",
        "🎯 MITRE ATT&CK",
        "🛡️ Response Recommendations",
        "📄 Incident Report",
        "🧠 Model & Evaluation"
    ]
)


# ==========================================================
# TAB 1 — INCIDENT INVESTIGATION
# ==========================================================

with tab1:

    st.header(
        "🔍 Detection Funnel"
    )


    funnel_df = pd.DataFrame({
        "Stage": [
            "Raw Security Events",
            "Anomalous Events",
            "Correlated Incident Events",
            "Confirmed Incidents"
        ],

        "Count": [
            total_events,
            total_anomalies,
            incident_event_count,
            confirmed_incidents
        ]
    })


    funnel_fig = px.funnel(
        funnel_df,
        x="Count",
        y="Stage",
        title=(
            "Raw Telemetry → Evidence-Backed Incidents"
        )
    )


    st.plotly_chart(
        funnel_fig,
        use_container_width=True
    )


    # ======================================================
    # PERFORMANCE
    # ======================================================

    st.header(
        "📊 Event-Level Detection Performance"
    )


    p1, p2, p3, p4 = st.columns(
        4
    )

    p1.metric(
        "Precision",
        f"{precision:.3f}"
    )

    p2.metric(
        "Recall",
        f"{recall:.3f}"
    )

    p3.metric(
        "F1",
        f"{f1:.3f}"
    )

    p4.metric(
        "False Positive Rate",
        f"{fpr:.4f}"
    )


    st.caption(
        "Controlled proof-of-concept evaluation. "
        "Ground truth is used only for evaluation."
    )

    st.divider()


    # ======================================================
    # INCIDENT SELECTION
    # ======================================================

    st.header(
        "🚨 Incident Investigation"
    )


    selected_incident = st.radio(
        "Select incident",
        incident_ids,
        horizontal=True,
        key="investigation_incident"
    )


    selected_summary = incidents[
        incidents[
            "incident_id"
        ].astype(str)
        ==
        selected_incident
    ].iloc[0]


    selected_events = incident_events[
        incident_events[
            "incident_id"
        ].astype(str)
        ==
        selected_incident
    ].copy()


    selected_events = (
        selected_events
        .sort_values(
            "timestamp"
        )
    )


    selected_relationships = relationships[
        relationships[
            "incident_id"
        ].astype(str)
        ==
        selected_incident
    ].copy()


    event_types = set(
        selected_events[
            "event_type"
        ]
    )


    if "FILE_COPY_USB" in event_types:

        attack_type = (
            "Potential USB Data Exfiltration"
        )

    elif "UPLOAD_EXTERNAL" in event_types:

        attack_type = (
            "Potential Cloud Data Exfiltration"
        )

    else:

        attack_type = (
            "Evidence-Backed Multi-Stage Activity"
        )


    st.error(
        f"{selected_summary['severity']} — "
        f"{attack_type}"
    )


    # ======================================================
    # SUMMARY
    # ======================================================

    a, b, c, d = st.columns(
        4
    )


    a.metric(
        "Incident",
        selected_incident
    )

    b.metric(
        "Affected User",
        selected_summary[
            "user"
        ]
    )

    c.metric(
        "Evidence",
        (
            f"{int(selected_summary['evidence_count'])}/"
            f"{int(selected_summary['evidence_total'])}"
        )
    )

    d.metric(
        "Severity",
        selected_summary[
            "severity"
        ]
    )


    a2, b2, c2, d2 = st.columns(
        4
    )


    evidence_percentage = int(
        round(
            float(
                selected_summary[
                    "evidence_completeness"
                ]
            )
            *
            100
        )
    )


    a2.metric(
        "Evidence Completeness",
        f"{evidence_percentage}%"
    )

    b2.metric(
        "Incident Duration",
        (
            f"{float(selected_summary['duration_minutes']):.1f} min"
        )
    )

    c2.metric(
        "Correlation Window",
        (
            f"{int(selected_summary['correlation_window_minutes'])} min"
        )
    )

    d2.metric(
        "Risk Score",
        (
            f"{int(selected_summary['risk_score'])}/100"
        )
    )


    st.caption(
        "Risk is an explainable prototype score based on "
        "anomaly strength and correlated evidence completeness."
    )


    # ======================================================
    # EVIDENCE GATE
    # ======================================================

    st.subheader(
        "🧩 Evidence Gate"
    )


    evidence_fields = [
        (
            "Suspicious Login",
            "suspicious_login"
        ),
        (
            "Sensitive Data Access",
            "sensitive_data_access"
        ),
        (
            "Suspicious Application",
            "suspicious_application"
        ),
        (
            "USB Activity",
            "usb_activity"
        ),
        (
            "Potential Exfiltration",
            "potential_exfiltration"
        )
    ]


    evidence_columns = st.columns(
        5
    )


    for column, (
        label,
        field
    ) in zip(
        evidence_columns,
        evidence_fields
    ):

        present = bool(
            int(
                selected_summary[
                    field
                ]
            )
        )

        column.markdown(
            f"### {'✅' if present else '➖'}\n"
            f"**{label}**"
        )


    st.divider()


    # ======================================================
    # TIMELINE
    # ======================================================

    st.header(
        "🕒 Reconstructed Attack Timeline"
    )


    for _, row in selected_events.iterrows():

        bytes_value = (
            int(
                row[
                    "bytes_transferred"
                ]
            )
            if pd.notna(
                row[
                    "bytes_transferred"
                ]
            )
            else 0
        )


        st.markdown(
            f"""
### {row['timestamp']} — {row['event_type']}

**Telemetry Source:** `{safe_value(row, 'log_source')}`  
**User:** `{safe_value(row, 'user')}`  
**Device:** `{safe_value(row, 'device')}`  
**Source IP:** `{safe_value(row, 'source_ip')}`  
**Application:** `{safe_value(row, 'application')}`  
**Resource:** `{safe_value(row, 'resource')}`  
**USB Device:** `{safe_value(row, 'usb_id')}`  
**Destination:** `{safe_value(row, 'destination')}`  
**Bytes Transferred:** `{bytes_value:,}`

**Anomaly Score:** `{float(row['anomaly_score']):.3f}`  
**Why suspicious:** `{safe_value(row, 'anomaly_reason')}`
"""
        )

        st.divider()


    # ======================================================
    # ENTITY GRAPH HELPERS
    # ======================================================

    def entity_events(entity):

        columns = [
            column
            for column in [
                "user",
                "device",
                "source_ip",
                "resource",
                "usb_id",
                "application",
                "destination"
            ]
            if column
            in selected_events.columns
        ]


        if not columns:

            return (
                selected_events.iloc[
                    0:0
                ]
            )


        mask = (
            selected_events[
                columns
            ]
            .fillna("")
            .astype(str)
            .eq(
                str(entity)
            )
            .any(
                axis=1
            )
        )


        return (
            selected_events[
                mask
            ]
            .sort_values(
                "timestamp"
            )
        )


    def relationship_events(
        source,
        destination,
        relation
    ):

        source = str(
            source
        )

        destination = str(
            destination
        )


        if relation == "CONNECTED_TO":

            mask = (
                selected_events[
                    "source_ip"
                ]
                .fillna("")
                .astype(str)
                .eq(source)

                &

                selected_events[
                    "user"
                ]
                .fillna("")
                .astype(str)
                .eq(destination)
            )


        elif relation == "USED_DEVICE":

            mask = (
                selected_events[
                    "user"
                ]
                .fillna("")
                .astype(str)
                .eq(source)

                &

                selected_events[
                    "device"
                ]
                .fillna("")
                .astype(str)
                .eq(destination)
            )


        elif relation == "USED_APPLICATION":

            mask = (
                selected_events[
                    "device"
                ]
                .fillna("")
                .astype(str)
                .eq(source)

                &

                selected_events[
                    "application"
                ]
                .fillna("")
                .astype(str)
                .eq(destination)
            )


        elif relation == "COPIED_TO":

            mask = (
                selected_events[
                    "resource"
                ]
                .fillna("")
                .astype(str)
                .eq(source)

                &

                selected_events[
                    "usb_id"
                ]
                .fillna("")
                .astype(str)
                .eq(destination)
            )


        elif relation == "UPLOADED_TO":

            mask = (
                selected_events[
                    "resource"
                ]
                .fillna("")
                .astype(str)
                .eq(source)

                &

                selected_events[
                    "destination"
                ]
                .fillna("")
                .astype(str)
                .eq(destination)
            )


        else:

            mask = (
                selected_events[
                    "device"
                ]
                .fillna("")
                .astype(str)
                .eq(source)

                &

                selected_events[
                    "resource"
                ]
                .fillna("")
                .astype(str)
                .eq(destination)
            )


        return (
            selected_events[
                mask
            ]
            .sort_values(
                "timestamp"
            )
        )


    # ======================================================
    # GRAPH
    # ======================================================

    st.header(
        "🕸 Dynamic Entity Graph"
    )


    G = nx.DiGraph()


    for _, relation_row in (
        selected_relationships
        .iterrows()
    ):

        source = str(
            relation_row[
                "source"
            ]
        )

        destination = str(
            relation_row[
                "destination"
            ]
        )

        relation = str(
            relation_row[
                "relationship"
            ]
        )


        G.add_node(
            source,
            node_type=relation_row[
                "source_type"
            ]
        )

        G.add_node(
            destination,
            node_type=relation_row[
                "destination_type"
            ]
        )

        G.add_edge(
            source,
            destination,
            relation=relation
        )


    if len(
        G.nodes
    ) > 0:

        pos = nx.spring_layout(
            G,
            seed=42,
            k=1.6
        )

        graph_traces = []


        for (
            source,
            destination,
            edge_data
        ) in G.edges(
            data=True
        ):

            x0, y0 = pos[
                source
            ]

            x1, y1 = pos[
                destination
            ]

            relation = edge_data[
                "relation"
            ]


            edge_events = relationship_events(
                source,
                destination,
                relation
            )


            hover = (
                f"<b>{relation}</b>"
                f"<br>{source}"
                f"<br>↓"
                f"<br>{destination}"
            )


            if not edge_events.empty:

                hover += (
                    "<br><br>"
                    "<b>Evidence Timeline</b>"
                )

                for _, event in (
                    edge_events
                    .head(6)
                    .iterrows()
                ):

                    hover += (
                        f"<br>"
                        f"{event['timestamp'].strftime('%H:%M:%S')}"
                        f" → "
                        f"{event['event_type']}"
                        f" | score "
                        f"{float(event['anomaly_score']):.3f}"
                    )


            graph_traces.append(
                go.Scatter(
                    x=[
                        x0,
                        x1
                    ],
                    y=[
                        y0,
                        y1
                    ],
                    mode="lines",
                    line=dict(
                        width=3
                    ),
                    text=[
                        hover,
                        hover
                    ],
                    hoverinfo="text",
                    showlegend=False
                )
            )


            graph_traces.append(
                go.Scatter(
                    x=[
                        (
                            x0 + x1
                        ) / 2
                    ],
                    y=[
                        (
                            y0 + y1
                        ) / 2
                    ],
                    mode="markers",
                    marker=dict(
                        size=30,
                        opacity=0.01
                    ),
                    hovertext=[
                        hover
                    ],
                    hoverinfo="text",
                    showlegend=False
                )
            )


        node_x = []
        node_y = []
        node_labels = []
        node_hovers = []
        node_sizes = []


        for node in G.nodes:

            x, y = pos[
                node
            ]

            node_x.append(
                x
            )

            node_y.append(
                y
            )

            node_labels.append(
                node
            )


            node_type = (
                G.nodes[
                    node
                ]
                .get(
                    "node_type",
                    "Entity"
                )
            )


            related_events = (
                entity_events(
                    node
                )
            )


            hover = (
                f"<b>{node}</b>"
                f"<br>Type: {node_type}"
            )


            if not related_events.empty:

                hover += (
                    f"<br>First seen: "
                    f"{related_events['timestamp'].min()}"
                )

                hover += (
                    f"<br>Last seen: "
                    f"{related_events['timestamp'].max()}"
                )

                hover += (
                    f"<br>Related events: "
                    f"{len(related_events)}"
                )

                hover += (
                    "<br><br>"
                    "<b>Timeline</b>"
                )


                for _, event in (
                    related_events
                    .head(8)
                    .iterrows()
                ):

                    hover += (
                        f"<br>"
                        f"{event['timestamp'].strftime('%H:%M:%S')}"
                        f" → "
                        f"{event['event_type']}"
                        f" | "
                        f"{float(event['anomaly_score']):.3f}"
                    )


            node_hovers.append(
                hover
            )


            node_sizes.append(
                50
                if node_type
                in {
                    "User",
                    "Device"
                }
                else 42
            )


        graph_traces.append(
            go.Scatter(
                x=node_x,
                y=node_y,
                mode="markers+text",
                text=node_labels,
                textposition="top center",
                hovertext=node_hovers,
                hoverinfo="text",
                marker=dict(
                    size=node_sizes,
                    line=dict(
                        width=2
                    )
                ),
                showlegend=False
            )
        )


        graph_fig = go.Figure(
            data=graph_traces
        )


        graph_fig.update_layout(
            title=(
                "Evidence-Linked Attack Entities"
            ),
            height=650,
            hovermode="closest",
            showlegend=False,
            xaxis=dict(
                visible=False
            ),
            yaxis=dict(
                visible=False
            ),
            margin=dict(
                l=20,
                r=20,
                t=60,
                b=20
            )
        )


        st.plotly_chart(
            graph_fig,
            use_container_width=True
        )


    st.caption(
        "Hover over nodes for entity history and relationships "
        "for the evidence timeline."
    )

    st.divider()


    # ======================================================
    # RELATIONSHIPS
    # ======================================================

    st.header(
        "🔗 Entity Relationships"
    )


    relationship_columns = [
        "source",
        "source_type",
        "relationship",
        "destination",
        "destination_type"
    ]


    st.dataframe(
        selected_relationships[
            relationship_columns
        ],
        use_container_width=True,
        hide_index=True
    )


    st.divider()


    # ======================================================
    # INCIDENT EVIDENCE
    # ======================================================

    st.header(
        "🔎 Incident Evidence"
    )


    analyst_columns = [
        "event_id",
        "timestamp",
        "log_source",
        "user",
        "event_type",
        "device",
        "source_ip",
        "application",
        "resource",
        "usb_id",
        "destination",
        "bytes_transferred",
        "anomaly_score",
        "anomaly_reason"
    ]


    analyst_columns = [
        column
        for column in analyst_columns
        if column
        in selected_events.columns
    ]


    st.dataframe(
        selected_events[
            analyst_columns
        ],
        use_container_width=True,
        hide_index=True
    )


# ==========================================================
# TAB 2 — FALSE POSITIVE SUPPRESSION
# ==========================================================

with tab2:

    st.header(
        "✅ False-Positive Suppression"
    )


    st.info(
        "ChainSight preserves suspicious activity for analyst visibility "
        "but requires correlated evidence before promoting it to an incident."
    )


    anomaly_users = set(
        logs[
            logs[
                "is_anomaly"
            ]
            == 1
        ]["user"]
    )

    incident_users = set(
        incidents[
            "user"
        ]
    )

    suppressed_users = (
        anomaly_users
        -
        incident_users
    )


    s1, s2, s3 = st.columns(
        3
    )

    s1.metric(
        "Users With Anomalies",
        len(
            anomaly_users
        )
    )

    s2.metric(
        "Incident Users",
        len(
            incident_users
        )
    )

    s3.metric(
        "Suppressed Users",
        len(
            suppressed_users
        )
    )


    st.divider()


    for user in sorted(
        suppressed_users
    ):

        user_events = logs[
            (
                logs["user"]
                == user
            )
            &
            (
                logs["is_anomaly"]
                == 1
            )
        ].copy()


        user_case = pd.DataFrame()


        if (
            not suppressed_cases.empty
            and
            "user"
            in suppressed_cases.columns
        ):

            user_case = (
                suppressed_cases[
                    suppressed_cases[
                        "user"
                    ]
                    == user
                ]
            )


        st.warning(
            f"Anomalous Activity — {user}"
        )


        if not user_case.empty:

            case = (
                user_case.iloc[0]
            )


            a, b, c = st.columns(
                3
            )

            a.metric(
                "Events",
                int(
                    case[
                        "event_count"
                    ]
                )
            )

            b.metric(
                "Evidence",
                (
                    f"{int(case['evidence_count'])}/"
                    f"{int(case['evidence_total'])}"
                )
            )

            c.metric(
                "Decision",
                "SUPPRESSED"
            )


        suppression_columns = [
            "timestamp",
            "log_source",
            "event_type",
            "device",
            "source_ip",
            "anomaly_score",
            "anomaly_reason"
        ]


        st.dataframe(
            user_events[
                suppression_columns
            ],
            use_container_width=True,
            hide_index=True
        )


        st.success(
            "No incident generated — insufficient correlated attack evidence."
        )

        st.divider()


# ==========================================================
# TAB 3 — MITRE ATT&CK
# ==========================================================

with tab3:

    st.header(
        "🎯 MITRE ATT&CK Semantic Mapping"
    )


    st.info(
        "ATT&CK is applied after reconstruction. "
        "Contextual mappings indicate behavioural consistency "
        "and are not treated as independent proof."
    )


    selected_mitre_incident = st.radio(
        "Select incident",
        incident_ids,
        horizontal=True,
        key="mitre_incident"
    )


    incident_mitre = mitre[
        mitre[
            "incident_id"
        ].astype(str)
        ==
        selected_mitre_incident
    ].copy()


    if incident_mitre.empty:

        st.info(
            "No ATT&CK mappings available."
        )

    else:

        incident_mitre = (
            incident_mitre
            .sort_values(
                "timestamp"
            )
        )


        unique_techniques = (
            incident_mitre[
                "technique_id"
            ]
            .nunique()
        )


        high_confidence = int(
            (
                incident_mitre[
                    "confidence"
                ]
                == "High"
            )
            .sum()
        )


        contextual = int(
            (
                incident_mitre[
                    "confidence"
                ]
                == "Contextual"
            )
            .sum()
        )


        m1, m2, m3 = st.columns(
            3
        )


        m1.metric(
            "Mapped Techniques",
            unique_techniques
        )

        m2.metric(
            "Direct / High Confidence",
            high_confidence
        )

        m3.metric(
            "Contextual Mappings",
            contextual
        )


        st.divider()


        for _, row in (
            incident_mitre
            .iterrows()
        ):

            icon = (
                "🔴"
                if row[
                    "confidence"
                ]
                == "High"
                else "🟡"
            )


            st.markdown(
                f"""
### {row['timestamp']} — {row['event_type']}

**{row['technique_id']} — {row['technique_name']}**

**Tactic:** `{row['tactic']}`  
**Confidence:** {icon} `{row['confidence']}`

**Evidence basis:**  
{row['evidence_basis']}
"""
            )

            st.divider()


        st.dataframe(
            incident_mitre[
                [
                    "timestamp",
                    "event_type",
                    "technique_id",
                    "technique_name",
                    "tactic",
                    "confidence",
                    "evidence_basis"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )


# ==========================================================
# TAB 4 — RESPONSE RECOMMENDATIONS
# ==========================================================

with tab4:

    st.header(
        "🛡️ Analyst Response Recommendations"
    )


    st.info(
        "ChainSight recommends response actions based on correlated evidence. "
        "It does not automatically execute containment actions."
    )


    selected_response_incident = st.radio(
        "Select incident",
        incident_ids,
        horizontal=True,
        key="response_incident"
    )


    response_summary = incidents[
        incidents[
            "incident_id"
        ].astype(str)
        ==
        selected_response_incident
    ].iloc[0]


    response_rows = remediation[
        remediation[
            "incident_id"
        ].astype(str)
        ==
        selected_response_incident
    ].copy()


    r1, r2, r3 = st.columns(
        3
    )


    r1.metric(
        "Affected User",
        response_summary[
            "user"
        ]
    )

    r2.metric(
        "Severity",
        response_summary[
            "severity"
        ]
    )

    r3.metric(
        "Recommended Actions",
        len(
            response_rows
        )
    )


    st.divider()


    priority_order = {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4
    }


    if not response_rows.empty:

        response_rows[
            "priority_order"
        ] = (
            response_rows[
                "priority"
            ]
            .map(
                priority_order
            )
            .fillna(
                99
            )
        )


        response_rows = (
            response_rows
            .sort_values(
                [
                    "priority_order",
                    "category"
                ]
            )
        )


        for _, row in (
            response_rows
            .iterrows()
        ):

            if row[
                "priority"
            ] == "CRITICAL":

                st.error(
                    f"🚨 {row['priority']} — "
                    f"{row['category']}"
                )

            elif row[
                "priority"
            ] == "HIGH":

                st.warning(
                    f"⚠️ {row['priority']} — "
                    f"{row['category']}"
                )

            else:

                st.info(
                    f"ℹ️ {row['priority']} — "
                    f"{row['category']}"
                )


            st.markdown(
                f"""
**Recommended action**

{row['recommendation']}

**Why ChainSight recommends it**

{row['rationale']}
"""
            )

            st.divider()


        st.subheader(
            "Response Plan"
        )


        st.dataframe(
            response_rows[
                [
                    "priority",
                    "category",
                    "recommendation",
                    "rationale"
                ]
            ],
            use_container_width=True,
            hide_index=True
        )


# ==========================================================
# REPORT GENERATOR
# ==========================================================

def generate_incident_report(
    incident_id
):

    summary = incidents[
        incidents[
            "incident_id"
        ].astype(str)
        ==
        incident_id
    ].iloc[0]


    events = incident_events[
        incident_events[
            "incident_id"
        ].astype(str)
        ==
        incident_id
    ].copy()


    events = (
        events
        .sort_values(
            "timestamp"
        )
    )


    relations = relationships[
        relationships[
            "incident_id"
        ].astype(str)
        ==
        incident_id
    ].copy()


    mitre_rows = mitre[
        mitre[
            "incident_id"
        ].astype(str)
        ==
        incident_id
    ].copy()


    recommendation_rows = remediation[
        remediation[
            "incident_id"
        ].astype(str)
        ==
        incident_id
    ].copy()


    evidence_percentage = round(
        float(
            summary[
                "evidence_completeness"
            ]
        )
        *
        100
    )


    report = f"""
<!DOCTYPE html>

<html>

<head>

<meta charset="UTF-8">

<title>
ChainSight Incident Report - {html.escape(incident_id)}
</title>

<style>

body {{
    font-family: Arial, sans-serif;
    margin: 40px;
    color: #222;
}}

h1 {{
    color: #174a7e;
}}

h2 {{
    border-bottom: 2px solid #dddddd;
    padding-bottom: 6px;
    margin-top: 32px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 12px;
}}

th, td {{
    border: 1px solid #dddddd;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}

th {{
    background: #f2f2f2;
}}

.critical {{
    color: #b00020;
    font-weight: bold;
}}

.box {{
    background: #f5f8fb;
    padding: 14px;
    border-left: 5px solid #174a7e;
    margin-bottom: 20px;
}}

.footer {{
    margin-top: 50px;
    font-size: 12px;
    color: #666666;
}}

</style>

</head>

<body>

<h1>
ChainSight AI Incident Report
</h1>

<div class="box">

<b>Incident ID:</b>
{html.escape(str(summary['incident_id']))}
<br>

<b>Affected User:</b>
{html.escape(str(summary['user']))}
<br>

<b>Severity:</b>
<span class="critical">
{html.escape(str(summary['severity']))}
</span>
<br>

<b>Risk Score:</b>
{int(summary['risk_score'])}/100
<br>

<b>Evidence Completeness:</b>
{evidence_percentage}%
<br>

<b>Incident Duration:</b>
{float(summary['duration_minutes']):.1f} minutes
<br>

<b>Correlation Window:</b>
{int(summary['correlation_window_minutes'])} minutes

</div>

<h2>
Evidence Gate
</h2>

<table>

<tr>
<th>Evidence Signal</th>
<th>Status</th>
</tr>

<tr>
<td>Suspicious Login</td>
<td>{"Present" if int(summary["suspicious_login"]) else "Not Present"}</td>
</tr>

<tr>
<td>Sensitive Data Access</td>
<td>{"Present" if int(summary["sensitive_data_access"]) else "Not Present"}</td>
</tr>

<tr>
<td>Suspicious Application</td>
<td>{"Present" if int(summary["suspicious_application"]) else "Not Present"}</td>
</tr>

<tr>
<td>USB Activity</td>
<td>{"Present" if int(summary["usb_activity"]) else "Not Present"}</td>
</tr>

<tr>
<td>Potential Exfiltration</td>
<td>{"Present" if int(summary["potential_exfiltration"]) else "Not Present"}</td>
</tr>

</table>

<h2>
Reconstructed Attack Timeline
</h2>

<table>

<tr>
<th>Timestamp</th>
<th>Source</th>
<th>Event</th>
<th>Device</th>
<th>IP</th>
<th>Resource</th>
<th>Anomaly Score</th>
<th>Reason</th>
</tr>
"""


    for _, row in events.iterrows():

        report += f"""
<tr>

<td>
{html.escape(str(row['timestamp']))}
</td>

<td>
{html.escape(str(safe_value(row, 'log_source')))}
</td>

<td>
{html.escape(str(row['event_type']))}
</td>

<td>
{html.escape(str(safe_value(row, 'device')))}
</td>

<td>
{html.escape(str(safe_value(row, 'source_ip')))}
</td>

<td>
{html.escape(str(safe_value(row, 'resource')))}
</td>

<td>
{float(row['anomaly_score']):.3f}
</td>

<td>
{html.escape(str(safe_value(row, 'anomaly_reason')))}
</td>

</tr>
"""


    report += """
</table>

<h2>
Entity Relationships
</h2>

<table>

<tr>
<th>Source</th>
<th>Source Type</th>
<th>Relationship</th>
<th>Destination</th>
<th>Destination Type</th>
</tr>
"""


    for _, row in relations.iterrows():

        report += f"""
<tr>

<td>
{html.escape(str(row['source']))}
</td>

<td>
{html.escape(str(row['source_type']))}
</td>

<td>
{html.escape(str(row['relationship']))}
</td>

<td>
{html.escape(str(row['destination']))}
</td>

<td>
{html.escape(str(row['destination_type']))}
</td>

</tr>
"""


    report += """
</table>

<h2>
MITRE ATT&CK Context
</h2>

<table>

<tr>
<th>Technique</th>
<th>Name</th>
<th>Tactic</th>
<th>Confidence</th>
<th>Evidence Basis</th>
</tr>
"""


    for _, row in mitre_rows.iterrows():

        report += f"""
<tr>

<td>
{html.escape(str(row['technique_id']))}
</td>

<td>
{html.escape(str(row['technique_name']))}
</td>

<td>
{html.escape(str(row['tactic']))}
</td>

<td>
{html.escape(str(row['confidence']))}
</td>

<td>
{html.escape(str(row['evidence_basis']))}
</td>

</tr>
"""


    report += """
</table>

<h2>
Recommended Response
</h2>

<table>

<tr>
<th>Priority</th>
<th>Category</th>
<th>Recommendation</th>
<th>Rationale</th>
</tr>
"""


    for _, row in (
        recommendation_rows
        .iterrows()
    ):

        report += f"""
<tr>

<td>
{html.escape(str(row['priority']))}
</td>

<td>
{html.escape(str(row['category']))}
</td>

<td>
{html.escape(str(row['recommendation']))}
</td>

<td>
{html.escape(str(row['rationale']))}
</td>

</tr>
"""


    report += f"""
</table>

<div class="footer">

Generated by ChainSight AI.<br>
This proof-of-concept report provides analyst decision support.
Response recommendations require human validation before execution.

</div>

</body>

</html>
"""


    return report


# ==========================================================
# TAB 5 — INCIDENT REPORT
# ==========================================================

with tab5:

    st.header(
        "📄 Analyst-Ready Incident Report"
    )


    st.info(
        "ChainSight converts the reconstructed attack story into "
        "an analyst-ready report containing evidence, timeline, entities, "
        "ATT&CK context and recommended response actions."
    )


    selected_report_incident = st.radio(
        "Select incident",
        incident_ids,
        horizontal=True,
        key="report_incident"
    )


    report_summary = incidents[
        incidents[
            "incident_id"
        ].astype(str)
        ==
        selected_report_incident
    ].iloc[0]


    q1, q2, q3, q4 = st.columns(
        4
    )


    q1.metric(
        "Incident",
        selected_report_incident
    )

    q2.metric(
        "User",
        report_summary[
            "user"
        ]
    )

    q3.metric(
        "Severity",
        report_summary[
            "severity"
        ]
    )

    q4.metric(
        "Risk",
        (
            f"{int(report_summary['risk_score'])}/100"
        )
    )


    st.divider()


    report_html = generate_incident_report(
        selected_report_incident
    )


    st.download_button(
        label=(
            "⬇️ Download Incident Report"
        ),

        data=report_html,

        file_name=(
            f"ChainSight_{selected_report_incident}_Incident_Report.html"
        ),

        mime="text/html",

        use_container_width=True
    )


    st.caption(
        "Open the downloaded HTML report in a browser. "
        "It can also be printed or saved as PDF."
    )


    st.subheader(
        "Report Contents"
    )


    st.markdown(
        """
The generated report contains:

- Incident identification
- User and severity
- Risk score
- Evidence completeness
- Correlation window
- Evidence gate results
- Reconstructed chronological timeline
- Entity relationships
- MITRE ATT&CK mappings
- Response recommendations
- Analyst-use disclaimer
"""
    )


# ==========================================================
# TAB 6 — MODEL & EVALUATION
# ==========================================================

with tab6:

    st.header(
        "🧠 Behavioural Baseline & Evaluation"
    )


    st.subheader(
        "Learned User Baselines"
    )


    st.caption(
        "Devices, IP addresses, applications and normal activity hours "
        "are derived from baseline telemetry."
    )


    if not baselines.empty:

        st.dataframe(
            baselines,
            use_container_width=True,
            hide_index=True
        )


    st.divider()


    # ======================================================
    # INCIDENT EVALUATION
    # ======================================================

    st.subheader(
        "Incident-Level Evaluation"
    )


    if not incident_evaluation.empty:

        evaluation_lookup = dict(
            zip(
                incident_evaluation[
                    "metric"
                ],
                incident_evaluation[
                    "value"
                ]
            )
        )


        e1, e2, e3, e4 = st.columns(
            4
        )


        e1.metric(
            "Attack Scenarios",
            int(
                evaluation_lookup.get(
                    "True Attack Scenarios",
                    0
                )
            )
        )

        e2.metric(
            "Reconstructed",
            int(
                evaluation_lookup.get(
                    "Reconstructed Attack Scenarios",
                    0
                )
            )
        )

        e3.metric(
            "Incident Precision",
            f"{float(evaluation_lookup.get('Incident Precision', 0)):.3f}"
        )

        e4.metric(
            "Incident Recall",
            f"{float(evaluation_lookup.get('Incident Recall', 0)):.3f}"
        )


        st.caption(
            "These results apply only to the controlled proof-of-concept scenarios."
        )


        st.dataframe(
            incident_evaluation,
            use_container_width=True,
            hide_index=True
        )


    st.divider()


    # ======================================================
    # ANOMALY DISTRIBUTION
    # ======================================================

    st.subheader(
        "📈 Anomaly Distribution"
    )


    anomaly_data = logs[
        logs[
            "is_anomaly"
        ]
        == 1
    ].copy()


    anomaly_fig = px.bar(
        anomaly_data,
        x="event_type",
        y="anomaly_score",
        color="user",
        hover_data=[
            "timestamp",
            "log_source",
            "device",
            "source_ip",
            "anomaly_reason"
        ],
        title=(
            "Anomalous Security Events"
        )
    )


    st.plotly_chart(
        anomaly_fig,
        use_container_width=True
    )


    st.divider()


    # ======================================================
    # ARCHITECTURE
    # ======================================================

    st.subheader(
        "🔄 ChainSight Processing Architecture"
    )


    st.markdown(
        """
**1. Multi-Source Telemetry**  
Authentication, file, device, application and network logs.

↓

**2. Normalization**  
Different telemetry sources are transformed into a common schema.

↓

**3. Learned Behavioural Baselines**  
Normal user devices, IP addresses, applications and working hours are learned.

↓

**4. Hybrid Anomaly Detection**  
Isolation Forest behaviour scoring is combined with explainable security context.

↓

**5. Temporal Entity Correlation**  
Related anomalous events are connected using entity continuity and a correlation window.

↓

**6. Evidence Gate**  
Isolated anomalies are retained but not automatically promoted to incidents.

↓

**7. Attack Reconstruction**  
Validated evidence becomes a chronological attack story and entity graph.

↓

**8. MITRE ATT&CK Enrichment**  
Reconstructed behaviour receives standardized semantic context.

↓

**9. Response Recommendation**  
ChainSight proposes evidence-driven analyst response actions.

↓

**10. Incident Reporting**  
The complete investigation is exported as an analyst-ready incident report.
"""
    )


# ==========================================================
# FOOTER
# ==========================================================

st.divider()

st.caption(
    "ChainSight AI — From isolated anomalies to evidence-backed attack stories."
)