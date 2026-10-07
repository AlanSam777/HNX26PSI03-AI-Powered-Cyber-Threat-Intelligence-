# ChainSight AI

## Evidence-Driven Multi-Stage Attack Reconstruction

ChainSight AI is a cybersecurity proof-of-concept designed to reduce SOC alert overload by converting isolated suspicious events into evidence-backed attack stories.

Traditional monitoring tools may generate large volumes of alerts. ChainSight AI focuses on connecting related activity across users, devices, IP addresses, applications, files, USB devices, and external destinations.

The core principle is:

> **An anomaly is not automatically an incident.**

ChainSight first detects unusual behaviour, then performs temporal and entity correlation, evaluates evidence, reconstructs the attack chain, and finally presents the result to the analyst.

---

# What the Project Does

ChainSight AI performs the following workflow:

1. Generates multi-source security telemetry
2. Normalizes different log sources into a common schema
3. Learns normal user behaviour
4. Detects behavioural anomalies using Isolation Forest
5. Adds contextual cybersecurity signals
6. Correlates suspicious activity across entities and time
7. Applies an evidence gate
8. Reconstructs multi-stage attack incidents
9. Maps reconstructed behaviour to MITRE ATT&CK
10. Generates response recommendations
11. Produces analyst-ready incident reports
12. Visualizes everything in a Streamlit dashboard

---

# Problem Statement

SOC analysts may receive very large numbers of alerts during daily operations.

Many of these alerts are isolated and may not represent a real attack.

The problem is therefore not only:

> "Can we detect unusual events?"

The more important question is:

> "Can we connect related events and determine whether they form a meaningful attack story?"

ChainSight AI addresses this by moving from:

```text
Individual Alerts
      ↓
Behavioural Anomalies
      ↓
Temporal + Entity Correlation
      ↓
Evidence Validation
      ↓
Attack Reconstruction
      ↓
Analyst Response