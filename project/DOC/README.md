# Hybrid SOC Threat Detector with MITRE ATT&CK STIX Integration

An advanced, containerized Hybrid Security Operations Center (SOC) threat detection system developed as part of an academic cybersecurity project at HIT (Holon Institute of Technology).

![Hybrid SOC Threat Detector Dashboard](docs/dashboard.png)

## System Architecture
The system is containerized using Docker Compose and consists of three modular components:
1. Simulator (`simulator.py`): Generates cyclic network traffic, logs, and simulated attack scenarios.
2. Detector Engine (`detector.py`): Runs signature matching, unsupervised machine learning (Isolation Forest), and CTI parsing via MITRE ATT&CK STIX bundles (`enterprise-attack-mini.json`).
3. Dashboard (`dashboard.py`): Streamlit web interface presenting operational findings, severity breakdowns, detection tables, and quantitative academic metrics.

## Key Features & Performance Metrics
- Hybrid Detection: Merges deterministic rules with anomaly detection to reduce false alerts.
- MITRE ATT&CK Mapping: Automated STIX object parsing to map threats to standard tactics and techniques.
- Academic Evaluation Metrics:
  - Precision: 0.8657
  - Recall: 0.9667
  - F1-Score: 0.9134
  - False Positive Rate (FPR): 0.1667

## Quick Start & Installation
Prerequisites: Docker & Docker Compose installed.

Running the System:
1. Clone the repository and navigate to the project directory:
   git clone https://github.com/shacharlaria/HIT-ai-cybersecurity-labs.git
   cd HIT-ai-cybersecurity-labs/project

2. Build and start the containers using Docker Compose:
   docker-compose up --build

3. Open your web browser and access the dashboard at:
   http://localhost:8000

## Project Structure
- dashboard.py: Streamlit operational & evaluation web interface
- detector.py: Core hybrid detection engine
- simulator.py: Network log & attack traffic generator
- Dockerfile & Dockerfile.dashboard: Container configurations
- docker-compose.yml: Multi-container orchestration setup
- mitre/: MITRE ATT&CK STIX JSON bundles
- output/: Generated system logs and detection reports

## Author & Course
- Student: Shachar Laria
- Advisor: Andrey Kozuchov
- Institution: HIT - Holon Institute of Technology
- Course: Artificial Intelligence-Driven Cybersecurity (Academic Semester Project)
```eof

This single, clean file structure resolves any formatting issues and displays smoothly. Let me know when you're ready for the presentation slides or any other component!איזה קוד או מסמך בדיוק נחתך? תן לינק או הדבק את החלק הרלוונטי כדי שאוכל לרכז ולכתוב לך את הכל ברצף אחד מלא.
