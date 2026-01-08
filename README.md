## 📊 Network Anomaly Detection System ##

### Purpose ###
####   Network Anomaly Detection System is a powerful, Python-based application designed to identify suspicious activities and potential security threats in network traffic data. Whether you're a network administrator, security analyst, or student learning about cybersecurity, this tool provides an intuitive interface to analyze network patterns and detect anomalies using machine learning algorithms. Its a personal project that intent to express my learning in data analysis and networking. ####

### What it does? ###

#### 
- Automatically detects unusual network behavior that could indicate security threats
- Analyzes network traffic patterns from CSV or PCAP files
- Visualizes data through multiple analytical views
- Generates professional reports with actionable insight
- Supports both dark and light mode for comfortable usage
####

### Limitations ###

#### As being said, This is made to express what I've learn in data analyst and networking. It also limitations since it is a small personal project. For its technical limits, file size (100 mb for csv and 50MB for PCAP). The system provides full support for TCP, UDP, and ICMP protocols. However, it offers limited analysis capabilities for encrypted traffic due to inherent constraints in inspecting encrypted payloads.For processing PCAP files, the system requires installation of the Scapy library. This dependency enables comprehensive packet analysis from captured network traffic files. Several detection limitations should be noted. False positives may occur where normal traffic patterns are flagged as anomalous in certain edge cases or unusual network configurations. Additionally, the system may not detect completely novel attack patterns without prior training or pattern recognition. Encrypted traffic presents another constraint, offering limited insight into packet contents due to encryption. Furthermore, the system lacks organizational context awareness and does not incorporate specific network policies that might influence threat assessment. The system supports Windows, Mac, and Linux platforms with Python 3.8 or higher. Minimum specifications include 4GB of RAM and 2GB of free disk space. For optimal performance, especially when working with larger datasets, 8GB or more of RAM is recommended to ensure efficient processing and analysis. ####

### How it work? ###

#### 1. Upload your network data (CSV or PCAP format)
#### First thing that will see 

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a78c67b6-9fb1-4201-ab3a-e6bfdfe9fce4" />

#### After uploading csv/PCAP
#### Overview with 3 tabs(Quick stats, Data Preview, Column Info)
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/a74f3116-51cc-4dbd-92cd-532857382a6c" />

#### Time Series
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/76b0850f-9650-440c-a3dc-203bf93b9da8" />

#### Distributions
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/ccc85eb9-7bd7-4f7c-a5f3-28a00e073d08" />

##### The user have a free will what size of graph they want, its orientation and save the graph.

#### For anomaly detection, you need to click the red button first for analyzing anomaly
##### There are choices for anomaly detection 
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/c7666921-43c8-4193-b61d-20fd592e5365" />

#### Protocols
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/41d8784d-5dd0-490f-8533-30f7fc9fa943" />

#### ARP Analysis

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/e488b987-c63b-4def-abcb-b9a1a0796cd6" />

#### Heatmap
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/382a8167-e18b-4444-9895-d7357102076d" />

#### Details
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/00bce63e-8f56-493a-acd8-ba601262a5dc" />

##### As you can see there is option for generating report and save as html file.



<img width="1091" height="879" alt="image" src="https://github.com/user-attachments/assets/c4eaa723-849c-487f-884b-7091773d06f3" />
<img width="752" height="777" alt="image" src="https://github.com/user-attachments/assets/2afac785-f1be-43ad-b0ea-3686c1f2ed9c" />



##### Disclaimer: The data that I used is data from wireshark.








