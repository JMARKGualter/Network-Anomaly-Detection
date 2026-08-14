# 📊 Network Anomaly Detection System

## Purpose

A Python-based application designed to identify suspicious activities and potential security threats in network traffic data. Built as a personal project to demonstrate practical learning in **data analysis, cybersecurity, and networking**.

---

## What It Does

* Automatically detects unusual network behavior that could indicate security threats
* Analyzes network traffic patterns from **CSV** or **PCAP** files
* Visualizes network data through multiple analytical views
* Generates professional reports with actionable insights

---

## Limitations

* **File Size Limits:** CSV files up to 100 MB; PCAP files up to 50 MB
* **Protocol Support:** TCP, UDP, and ICMP are fully supported; encrypted traffic has limited visibility
* **Detection:** May produce false positives and may not detect previously unknown attacks
* **System Requirements:** Python 3.8+, 4 GB RAM minimum (8 GB recommended), and 2 GB available disk space
* **PCAP Analysis:** Requires the Scapy library
* **Context Awareness:** Does not account for organization-specific security policies or network configurations

---

## How It Works

### 1. Upload Network Data

Upload your network traffic data in **CSV** or **PCAP** format.

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/754e940c-6d97-4847-83cb-0ee12b2ae64a" />


*The landing page where users upload their network data files.*

---

### 2. Analyze Data Through the Dashboard

The system provides multiple analytical views for examining network traffic and identifying potential anomalies.

<img width="1919" height="1079" alt="image" src="https://github.com/user-attachments/assets/4f01c84e-10b5-4da4-8ff3-a0b8c3c22b08" />



*The main dashboard provides overview, time series, distributions, anomaly detection, protocol analysis, ARP analysis, heatmap, and detailed network traffic views.*

---

### 3. Generate Reports

Generate professional reports containing analysis results and actionable insights. Reports can be saved as **HTML files** for further review or documentation.

<img width="972" height="740" alt="image" src="https://github.com/user-attachments/assets/def9e6bb-1c3f-46fe-9197-eb930b926e2d" />


*The report generation interface provides interpretations and insights based on the analyzed network traffic.*

---

## Quick Install

Install the required Python dependencies:

```bash
pip install pandas numpy scikit-learn matplotlib seaborn scapy
```

## Run

Start the application with:

```bash
python dashboard.py
```

---

## Technologies Used

* **Python**
* **Pandas**
* **NumPy**
* **Scikit-learn**
* **Matplotlib**
* **Seaborn**
* **Scapy**

---

## Disclaimer

The network traffic data used in this project was obtained from **Wireshark captures** and is intended for educational and research purposes.
