# Hybrid SOC Threat Detector with MITRE ATT&CK STIX Integration

An advanced, containerized Hybrid Security Operations Center (SOC) threat detection system developed as part of an academic cybersecurity project at HIT (Holon Institute of Technology). The system bridges the gap between traditional signature-based detection and unsupervised anomaly detection, enriched with dynamic Cyber Threat Intelligence (CTI) from the **MITRE ATT&CK STIX** framework.

---

## 🏛️ System Architecture

The system is fully containerized using **Docker Compose** and consists of three main modular components:

1. **Simulator (`simulator.py`):** Generates cyclic network traffic, operational logs, and simulated attack scenarios to test system resilience and behavior under load.
2. **Detector Engine (`detector.py`):** Runs a two-tier detection pipeline:
   - **Signature-based Engine:** Cross-references logs against deterministic rules and known attack signatures.
   - **Unsupervised Machine Learning (Isolation Forest):** Analyzes behavioral IP feature vectors and connection patterns to flag statistical anomalies and zero-day behaviors.
   - **CTI Parser:** Dynamically loads and resolves threat indicators against MITRE ATT&CK STIX bundles (`enterprise-attack-mini.json`).
3. **Dashboard (`dashboard.py`):** An interactive **Streamlit** operational web dashboard that presents real-time operational findings, severity breakdowns, detection tables, and quantitative academic performance metrics.

---

## 📊 Key Features & Capabilities

- **Hybrid Detection:** Combines deterministic rule-matching with machine learning anomaly detection to reduce false positives while maintaining high sensitivity to novel threats.
- **MITRE ATT&CK Mapping:** Automated STIX object parsing to map detected anomalies to standardized tactics, techniques, and evidence logs.
- **Academic Evaluation Pipeline:** Computes core quantitative metrics to validate detection efficiency:
  - **Precision (~0.87):** High reliability of generated alerts.
  - **Recall (~0.96):** Exceptional coverage of simulated attack scenarios.
  - **F1-Score (~0.91):** Optimal balance between accuracy and sensitivity.
  - **False Positive Rate (FPR ~0.15):** Minimized noise for SOC analysts.

---

## 🚀 Quick Start & Installation

### Prerequisites
- [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/) installed on your machine.

### Running the System
1. Clone the repository and navigate to the project directory:
   
```bash
   git clone [https://github.com/shacharlaria/HIT-ai-cybersecurity-labs.git](https://github.com/shacharlaria/HIT-ai-cybersecurity-labs.git)
   cd HIT-ai-cybersecurity-labs/project
