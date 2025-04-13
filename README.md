# Security Audit Report for Linux

## Description
The **Security Audit Report Generator for Linux** is a Python-based tool designed to automate security audits on Linux servers. It evaluates the system's configurations, identifies potential vulnerabilities, and generates a detailed report with actionable recommendations. This tool is ideal for system administrators, security professionals, and audit teams.

---

## Features
- **Firewall Analysis**:
  - Checks if UFW (Uncomplicated Firewall) is active and lists its rules.
  - Displays all `iptables` rules.
- **Service Audit**:
  - Lists all running services.
  - Detects insecure services like Telnet or FTP.
- **SSH Security Check**:
  - Ensures root login over SSH is disabled.
  - Verifies that password-based authentication is turned off.
- **Sudoers Configuration**:
  - Displays the current sudoers file for review.
- **Disk Usage**:
  - Reports disk usage statistics.
- **Pending Updates**:
  - Checks for updates and pending software upgrades.
- **User Accounts Audit**:
  - Lists all system users and their login shells.
- **Open Ports**:
  - Displays all open ports and their associated processes.

---

## Requirements
- Python 3.8 or higher
- Root privileges for certain checks (e.g., firewall, open ports, updates)
- Compatible with Linux distributions like Ubuntu, Debian, CentOS, etc.

---

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/diegomessiah/security-audit-report-linux.git
   cd security-audit-report-linux
   ```

2. Ensure Python 3.8 or higher is installed on your system.

---

## Usage
1. Open a terminal.
2. Run the script with root privileges:
   ```bash
   sudo python3 security_audit_report_linux.py
   ```

3. The script generates a detailed report in the current directory with a filename like:
   ```
   security_audit_report_linux_YYYYMMDD_HHMMSS.txt
   ```

---

## Example Report
```plaintext
Security Audit Report - 2025-04-13 22:30:14
==================================================
Firewall Configuration:
- UFW is active. Rules:
Status: active
To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
80/tcp                     ALLOW       Anywhere

iptables Rules:
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22

Running Services:
UNIT                           LOAD   ACTIVE SUB     DESCRIPTION
cron.service                   loaded active running Regular background program processing daemon
ssh.service                    loaded active running OpenBSD Secure Shell server

SSH Configuration:
- Root login over SSH is disabled.
- Password authentication over SSH is enabled.

Disk Usage:
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1       100G   20G   80G  20% /

Pending Updates:
- 2 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.

Open Ports:
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd
==================================================
```

---

## Customization
- **Add New Checks**: Extend the script to include additional security checks.
- **Automate Audits**: Schedule the script to run periodically using `cron` or systemd timers.

---

## License
This project is licensed under the [MIT License](LICENSE).

---

## Contributions
Contributions are welcome! Feel free to submit a pull request or open an issue to improve the tool.

---

## Author
**Diego Messiah**
- GitHub: [diegomessiah](https://github.com/diegomessiah)
