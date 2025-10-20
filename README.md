# 🛡️ CyberHaven – A Safe Haven for Small Business Networks

## Overview
**CyberHaven Guardian** is a free, open-source cybersecurity tool designed to **detect, trap, and alert** on malicious activity in **real time**.

Built with small businesses and everyday users in mind, CyberHaven acts as a **lightweight digital shield** — monitoring network traffic, identifying threats, and automatically isolating suspicious activity **without requiring expensive enterprise-grade tools or complex setup.**

👉 Our mission is simple: **make powerful cybersecurity accessible to everyone.**

---

## ✨ Features
- **Honeynet Containment:** Automatically isolates malicious traffic into a secure sandbox for analysis.
- **Real-Time Detection:** Identifies port scans, callbacks, brute-force attempts, and beaconing.
- **IPv4 & IPv6 Support:** Dual-stack traffic analysis for modern networks.
- **TLS Fingerprint (JA3) Analysis:** Detects encrypted malware traffic without needing decryption.
- **C2 Beacon Detection:** Flags repetitive, timed patterns linked to command-and-control servers.
- **Alerting System:** Sends actionable alerts locally or via webhook (e.g., Slack, Discord).
- **Firewall & IDS Integration:** Connect to your existing security stack to automate blocking or responses.

---

## ⚙️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/<your-username>/CyberHaven-A-safe-haven-for-small-business-networks.git
cd CyberHaven-A-safe-haven-for-small-business-networks

2️⃣ Build the Project

mkdir build && cd build
cmake ..
make

3️⃣ Run the Tool

./cyberhaven-guardian

🔧 Configuration
config/cyberhaven.conf

config/filter.bpf
(tcp and (port 22 or port 3389 or port 443)) or (udp and port 53) or (tcp and portrange 5900-5910)

📊 Example Output

[ALERT] rule=PORT_SCAN sev=HIGH src=192.168.1.55 dst=10.0.0.12:22 reason=Multiple unique destination ports detected
[ALERT] rule=TLS_BEACON sev=HIGH src=2001:db8::4 dst=2607:f8b0::443 reason=Repetitive interval TLS traffic detected
[ALERT] rule=JA3_MATCH sev=CRITICAL src=10.0.0.10 dst=8.8.8.8:443 reason=Known malware TLS fingerprint matched

🗺️ Roadmap

- [ ] Add graphical web dashboard
- [ ] Integrate email & SMS alert notifications
- [ ] Implement machine learning anomaly detection
- [ ] Raspberry Pi deployment version
- [ ] Docker support for cloud deployments

🤝 Contributing

Contributions are welcome! If you’d like to improve CyberHaven, submit a pull request or open an issue. Whether it’s adding a feature, fixing a bug, or improving documentation — your input makes this project stronger.

👨‍💻 About the Developer

Created by Eddie Ocon, a cybersecurity student and developer passionate about building practical tools that protect small businesses and make the internet a safer place for everyone.

“My mission is simple: empower people with free, accessible cybersecurity solutions that truly make a difference.”

📜 License

MIT License

Copyright (c) 2025 Eddie Ocon

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction...




