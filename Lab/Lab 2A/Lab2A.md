# Lab 2A – Morpheus Lite: AI-Driven Cyber Governance with Human-in-the-Loop

This repository contains the results of Lab 2A, focusing on interpreting AI-driven security detections and applying human-in-the-loop (HITL) governance decisions using the Morpheus Lite framework.

## System Architecture & Pipeline Execution

### 1. Infrastructure Backbone (Redpanda / Kafka)
The lab uses Docker to host a Redpanda cluster as the real-time message broker, ingesting raw security telemetry and streaming it to the detection and agent orchestration engines.

![Redpanda Cluster Status](screenshots/01_redpanda_cluster.png)
*Figure 1: Redpanda Console verifying that the cluster and message brokers are running.*

---

### 2. Detection & SOC Analyst Dashboard
The stream of events is evaluated in real time. Anomalies are scored and presented on the Streamlit Analyst Dashboard (`Morpheus Lite Agentic SOC Dashboard`), allowing analysts to inspect pending human reviews.

![SOC Dashboard Overview](screenshots/02_soc_dashboard.png)
*Figure 2: SOC Dashboard showing ingested cases, high-risk flags, and pending reviews.*

---

### 3. AI Governance & Decision Context (Evidence, RAI, Meta-AI)
When inspecting a specific case, the dashboard provides the analytical breakdown:
* **Evidence Collection:** Specific behavioral indicators (e.g., failed logins, fingerprint deviations).
* **RAI Decision:** Governance agent ensuring safe mitigation policies.
* **Meta-AI Review:** Supervisory agent verifying inference quality and uncertainty.

![Case Analysis, RAI, and Meta-AI Review](screenshots/03_case_analysis.png)
*Figure 3: Deep-dive view showing Evidence context, RAI policy recommendations, and Meta-AI review.*

---

## Final Reflection: Selected Case Analysis (`alert-0-98`)

### Selected Case Summary

| Parameter | Details |
| :--- | :--- |
| **Alert ID** | `alert-0-98` |
| **Risk Score** | `100` |
| **User** | `svc-backup` |
| **Host** | `vpn-gw` |
| **Event Type** | `privilege_escalation` |
| **Fingerprint Deviation** | `298.9162` ($z$-score) |
| **Human Decision** | `escalate` |

### Reflection Questions & Answers

#### 1. Which evidence most influenced your decision?
The combination of a critical event type (`privilege_escalation`) on sensitive edge network infrastructure (`vpn-gw`) and an extreme user-specific fingerprint deviation ($z = 298.9162$) was the primary driver. Unlike low-severity anomalies, a service account (`svc-backup`) attempting privilege escalation on a VPN gateway with a massive behavioral anomaly indicates potential account compromise and lateral movement rather than routine automated behavior.

#### 2. Did your decision agree with the AI recommendation? Why or why not?
Yes, my decision agreed with escalating the case. Given the maximum risk score of $100$ and the high potential impact of unauthorized privilege escalation on critical network infrastructure, immediate escalation for human analyst investigation was fully justified.

#### 3. Did the RAI policy meaningfully constrain the action?
Yes, the Responsible AI (RAI) policy required explicit HITL validation before executing destructive or isolating actions. Because `vpn-gw` represents critical infrastructure, automated shutdown or credential revocation could cause severe operational downtime. The policy ensured safety while escalating the threat for review.

#### 4. Did the Meta-AI review identify uncertainty or challenge the recommendation?
The Meta-AI review approved the decision while pointing out the necessity to cross-reference whether an emergency maintenance window was active for `svc-backup`. However, given the high risk score and anomaly magnitude, the Meta-AI review supported human escalation without attempting automated mitigation.

#### 5. What additional evidence would have changed your decision?
* **To downgrade the alert:** Discovery of a documented, pre-approved change request covering system maintenance on `vpn-gw` at that timestamp.
* **To confirm immediate containment:** Endpoint detection logs showing process injection, LSASS memory dumping, or unexpected outbound connections following the escalation attempt.

#### 6. At what point in the pipeline should human authority be strongest?
Human authority must be strongest immediately prior to response execution, especially when intended actions are destructive, disruptive, or irreversible (such as locking critical service accounts or isolating gateway servers). Automated systems excel at detection and scoring, but humans must evaluate business context to prevent outage risks.

#### 7. What are the risks of automatically executing the recommended action?
* **Operational Disruption:** Automatically locking `svc-backup` or isolating `vpn-gw` could sever remote access for the entire organization or halt critical backup pipelines.
* **Adversarial Exploitation:** Attackers could deliberately trigger alerts on critical assets to trick automated systems into shutting down critical services, creating a self-inflicted Denial-of-Service (DoS).
