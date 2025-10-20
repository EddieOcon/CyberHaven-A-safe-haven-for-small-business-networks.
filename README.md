# 🛡️ CyberHaven – A Safe Haven for Small Business Networks

### 📜 Overview
**CyberHaven** is a free, open-source cybersecurity tool designed to **detect, trap, and alert** on malicious activity in real time.  
Built with small businesses and everyday users in mind, CyberHaven acts as a lightweight **digital shield**, monitoring network traffic, identifying threats, and automatically isolating suspicious activity — all without expensive enterprise-grade tools or complex setup.

Our mission is simple: **make powerful cybersecurity accessible to everyone.**

---

## 🚀 Features

-  **Honeynet Containment:** Automatically isolates malicious traffic into a secure sandbox for analysis.
-  **Real-Time Detection:** Identifies port scans, malware callbacks, brute-force attempts, and beaconing.
-  **IPv4 & IPv6 Support:** Full dual-stack monitoring for modern networks.
-  **HTTPS/TLS Analysis:** Detects malicious encrypted traffic using JA3 fingerprinting — without needing decryption.
-  **C2 Beacon Detection:** Flags repetitive, timed communication patterns associated with command-and-control servers.
-  **Alerting System:** Sends clear, actionable alerts locally or via webhook (e.g., Slack, Discord).
-  **Firewall & IDS Integration:** Can connect directly to your firewall or IDS to automate blocking or response.

---

##  Why I Built CyberHaven

Small businesses are targeted by cybercriminals every day — and most don’t have the resources to defend themselves.  
I built CyberHaven to **change that.** It’s my way of giving back to the community: a free, practical defense tool that anyone can use to protect their digital assets.

This project is also part of a bigger vision — to create tools that make the internet a safer place for families, small businesses, and organizations around the world.

---

## ⚙️ How It Works

1. **Capture:** CyberHaven passively monitors network traffic using `libpcap`.
2. **Analyze:** Each packet is inspected for signs of malicious behavior, unusual patterns, or known attack signatures.
3. **Contain:** Suspicious traffic is automatically diverted into a honeynet for safe observation.
4. **Alert:** Real-time alerts are generated with detailed context to support fast decision-making.

---

##  Tech Stack

- **Language:** C++ (lightweight, high-performance, and native on most systems)
- **Libraries:** `libpcap`, `libcurl`, `OpenSSL`
- **Platform:** Linux / macOS (Windows support planned)

---

##  Installation

```bash
# Install dependencies
sudo apt install build-essential libpcap-dev libcurl4-openssl-dev libssl-dev

# Clone the repository
git clone https://github.com/<your-username>/CyberHaven.git
cd CyberHaven

# Compile the project
g++ -std=c++17 -O2 -pthread -o cyberhaven main.cpp -lpcap -lcurl -lssl -lcrypto

# Run with elevated privileges
sudo ./cyberhaven
