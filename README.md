# 🛡️ NetGuard – Automated Network Reconnaissance & Security Assessment Tool

NetGuard is a Python-based network reconnaissance and preliminary security assessment tool that integrates **Nmap** with a **Flask web dashboard**.

It helps users discover active hosts, identify open ports, detect running services and highlight potential security exposures within authorized private networks.

## 🚀 Features

- **Network Scanning:** Scan authorized private IPv4 networks.
- **Host Discovery:** Identify active hosts.
- **Port Scanning:** Detect open ports.
- **Service Detection:** Identify running services and versions using Nmap.
- **Security Assessment:** Rule-based identification of potentially risky services and ports.
- **Web Dashboard:** Interactive dashboard built with Flask.
- **Risk Overview:** Visual summary of High, Medium and Informational findings.
- **Scan History:** Store and view previous scan results using SQLite.
- **Detailed Reports:** View scan details and download HTML security reports.

## 🛠️ Technologies Used

- Python
- Nmap
- Flask
- SQLite
- HTML
- CSS
- Git & GitHub

## 📋 Requirements

- Kali Linux or another Debian-based Linux distribution
- Python 3
- Nmap
- Git

## ⚙️ Installation

### 1. Install required packages

```bash
sudo apt update
sudo apt install -y nmap python3 python3-venv python3-pip git
```

### 2. Clone the repository

```bash
git clone https://github.com/azim-ahmad/NetGuard.git
```

### 3. Enter the project directory

```bash
cd NetGuard
```

### 4. Create a virtual environment

```bash
python3 -m venv venv
```

### 5. Activate the virtual environment

```bash
source venv/bin/activate
```

### 6. Install Flask

```bash
pip install flask
```

## ▶️ Usage

Run the application:

```bash
python app.py
```

Open your browser and visit:

```text
http://127.0.0.1:5000
```

Enter an authorized private network CIDR in the dashboard to start scanning.

Example:

```text
192.168.56.0/24
```

For local testing:

```text
127.0.0.1/32
```

## 📊 Project Structure

```text
NetGuard/
│
├── app.py
├── scanner.py
├── analyzer.py
├── templates/
│   ├── index.html
│   ├── history.html
│   └── scan_details.html
│
├── .gitignore
└── README.md
```

## 🔐 Security & Responsible Usage

- Scan only networks and systems you own or have explicit permission to assess.
- NetGuard restricts scanning to private IPv4 networks.
- Network size is limited to a maximum of 256 addresses.
- Do not use this tool against unauthorized networks.

## ⚠️ Limitations

- Security findings are based on predefined rules and indicate potential exposures, not confirmed vulnerabilities.
- NetGuard is not a CVE scanner or penetration-testing framework.
- Service and version detection depends on Nmap's detection capabilities.
- Findings should be manually verified.

## 👨‍💻 Author

**Azim Ahmad**

GitHub: [@azim-ahmad](https://github.com/azim-ahmad)

---

⭐ If you find this project useful, consider giving it a star!
