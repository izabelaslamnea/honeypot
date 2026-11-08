
# 🛡️ HONEYPOT — Security Operations Center

A Python-based TCP honeypot designed to simulate a fake administrative login panel, record connection attempts, detect potential brute-force activity and monitor suspicious interactions through a graphical dashboard.

## 🚀 Features

- **TCP Honeypot:** Simulates a fake administrative login service.
- **Connection Monitoring:** Records incoming connections and usernames.
- **IP Tracking:** Identifies and tracks unique IP addresses.
- **Brute-Force Detection:** Detects 5 or more failed login attempts from the same IP within 2 minutes.
- **Live Security Dashboard:** Displays connections, unique IPs and threat alerts.
- **Event Logging:** Records security events with timestamps.
- **CSV Export:** Exports collected events into CSV reports.
- **Visual Alerts:** Highlights detected threats in the dashboard.

## 🖥️ Dashboard

The graphical interface provides real-time visibility into:

- Total connections.
- Unique IP addresses.
- Detected threat alerts.
- Live security events.
- Detected IP addresses.

## 🛠️ Technologies

- Python 3
- Tkinter
- TCP Sockets
- Threading
- Queue
- CSV
- Logging

## 📦 Requirements

Python 3.10 or newer.

All libraries used in this project are included in the Python standard library.

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/izabelaslamnea/honeypot.git
```

Navigate into the project directory:

```bash
cd honeypot
```

## ▶️ Usage

Start the Honeypot server and dashboard:

```bash
python honeypot_gui.py
```

In a second terminal, run the test client:

```bash
python client_test.py
```

The test client generates five simulated login attempts using fictitious credentials.

## 📊 Brute-Force Detection

The system monitors failed login attempts by source IP.

A security alert is generated when an IP address reaches the configured threshold of five attempts within a two-minute window.

## 🔐 Security Notes

- This project is designed for educational purposes and controlled laboratory environments.
- The server listens exclusively on `127.0.0.1`.
- It is not a real SSH service.
- Passwords are not stored or written to the logs.
- Only fictitious credentials should be used during testing.
- Do not expose this experimental service to public networks.

## 🎯 Project Objectives

This project explores practical cybersecurity concepts:

- Network programming.
- Honeypot design.
- Intrusion detection.
- Brute-force monitoring.
- Security event logging.
- Basic SOC dashboard development.

## 👩‍💻 Author

**Izabela**

GitHub: [@izabelaslamnea](https://github.com/izabelaslamnea)
