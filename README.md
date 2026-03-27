# Cyber-Risk-Threat-Intelligence-Platform
# 🛡️ CyberScan Pro

### Network Cyber Risk & Threat Intelligence Platform

---

## 📌 Overview

CyberScan Pro is a **full-stack cybersecurity platform** that performs real-time **network scanning, threat intelligence enrichment, and risk analysis**.

It integrates tools like **Nmap, VirusTotal, Streamlit, and FastAPI** to simulate a real-world **Security Operations Center (SOC)**.

### 🔥 What it provides:
- 📊 Interactive dashboard  
- 🚨 Risk-based vulnerability analysis  
- 📩 Email alerts for critical issues  
- 📄 PDF report generation  
- 💾 Scan history tracking  

---

## 🎯 Key Features

### 🔍 Network Scanning (Nmap)
- Detects:
  - Open ports  
  - Running services  
  - Product & version  
- Command used: `nmap -sV`

---

### 🌐 Threat Intelligence (VirusTotal)
- Provides:
  - Malicious reports  
  - Suspicious counts  
  - Reputation score  
  - Country & network info  
  - Threat categories  

---

### 🧠 Risk Analysis Engine

Each service is scored using:

| Score Type     | Description                                 |
|---------------|---------------------------------------------|
| Exposure Score| Risk of exposed service (e.g., Telnet, RDP) |
| Threat Score  | Based on VirusTotal reports                 |
| Context Score | Country + threat category                   |
| Risk Score    | Final weighted score                        |

---

### 🚨 Severity Classification
- 🟢 Low  
- 🟡 Medium  
- 🟠 High  
- 🔴 Critical  

---

### 📊 Interactive Dashboard (Streamlit)
- KPI Cards (IP, Ports, Risk, Threat)
- 📈 Bar charts (Score breakdown)
- 🥧 Pie chart (Risk distribution)
- 🔥 Heatmap visualization
- 🌐 Services detected
- 📜 Scan history
- 📈 Risk trends over time

---

### 📩 Email Alerts
- Automatically sends email after scan  
- Includes:
  - Critical vulnerabilities  
  - Recommendations  

---

### 📄 PDF Report Generation
- Downloadable report including:
  - Summary  
  - Findings  
  - Risk levels  
  - Recommendations  

---

### ⚡ FastAPI Backend
- Provides API endpoints for:
  - Scan data  
  - History  
  - Analysis  
- Secured using API Key  

---

### 💾 Database (SQLite)
Stores:
- Scan results  
- Risk scores  
- History  

---

## 🗂️ Project Structure
