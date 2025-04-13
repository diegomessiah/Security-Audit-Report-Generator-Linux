import os
import subprocess
from datetime import datetime

class SecurityAuditLinux:
    def __init__(self):
        self.report = []

    def run_command(self, command):
        """Execute a shell command and return its output."""
        try:
            result = subprocess.check_output(command, shell=True, text=True)
            return result.strip()
        except subprocess.CalledProcessError as e:
            return f"Error executing command: {e}"

    def check_firewall(self):
        """Analyze firewall configurations."""
        self.report.append("Firewall Configuration:")
        # Check if UFW is active
        ufw_status = self.run_command("sudo ufw status")
        if "inactive" in ufw_status.lower():
            self.report.append("- UFW (Uncomplicated Firewall) is inactive. Consider enabling it.")
        else:
            self.report.append("- UFW is active. Rules:")
            self.report.append(ufw_status)

        # Check iptables rules
        self.report.append("\niptables Rules:")
        iptables_rules = self.run_command("sudo iptables -L -v -n")
        self.report.append(iptables_rules if iptables_rules else "- No iptables rules found.")

    def check_services(self):
        """Detect unnecessary or insecure services."""
        self.report.append("\nRunning Services:")
        # List active services
        services = self.run_command("systemctl list-units --type=service --state=running")
        self.report.append(services if services else "- No active services found.")

        # Check for specific insecure services
        insecure_services = ["telnet", "ftp"]
        for service in insecure_services:
            status = self.run_command(f"systemctl is-active {service}")
            if "active" in status:
                self.report.append(f"- Warning: {service} service is running. Consider disabling it.")

    def check_ssh_security(self):
        """Check SSH configuration for best practices."""
        self.report.append("\nSSH Configuration:")
        # Check if SSH root login is disabled
        ssh_config = self.run_command("sudo cat /etc/ssh/sshd_config | grep -i 'PermitRootLogin'")
        if "no" in ssh_config.lower():
            self.report.append("- Root login over SSH is disabled.")
        else:
            self.report.append("- Warning: Root login over SSH is enabled. Disable it by setting 'PermitRootLogin no' in sshd_config.")

        # Check if password authentication is disabled
        ssh_password = self.run_command("sudo cat /etc/ssh/sshd_config | grep -i 'PasswordAuthentication'")
        if "no" in ssh_password.lower():
            self.report.append("- Password authentication over SSH is disabled (good practice).")
        else:
            self.report.append("- Warning: Password authentication over SSH is enabled. Disable it by setting 'PasswordAuthentication no'.")

    def check_sudoers(self):
        """Check for unnecessary sudo privileges."""
        self.report.append("\nSudoers Configuration:")
        sudoers = self.run_command("sudo cat /etc/sudoers")
        self.report.append("- Review the following sudoers configuration for unnecessary permissions:")
        self.report.append(sudoers if sudoers else "- Could not retrieve sudoers configuration.")

    def check_disk_usage(self):
        """Analyze disk usage."""
        self.report.append("\nDisk Usage:")
        disk_usage = self.run_command("df -h")
        self.report.append(disk_usage if disk_usage else "- Could not retrieve disk usage information.")

    def check_updates(self):
        """Check for pending updates."""
        self.report.append("\nSystem Updates:")
        updates = self.run_command("sudo apt-get -s upgrade | grep -P '^\d+ upgraded'")
        if updates:
            self.report.append("- Pending updates:")
            self.report.append(updates)
        else:
            self.report.append("- The system is up-to-date.")

    def check_users(self):
        """List all users and their shells."""
        self.report.append("\nUser Accounts:")
        users = self.run_command("cat /etc/passwd | awk -F: '{print $1, $7}'")
        self.report.append(users if users else "- Could not retrieve user accounts.")

    def check_open_ports(self):
        """Check for open ports."""
        self.report.append("\nOpen Ports:")
        open_ports = self.run_command("sudo netstat -tulpn")
        self.report.append(open_ports if open_ports else "- No open ports detected.")

    def generate_report(self):
        """Generate a detailed security audit report."""
        self.report.append(f"Security Audit Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.report.append("=" * 50)
        self.check_firewall()
        self.check_services()
        self.check_ssh_security()
        self.check_sudoers()
        self.check_disk_usage()
        self.check_updates()
        self.check_users()
        self.check_open_ports()
        self.report.append("=" * 50)

        # Save the report to a file
        report_path = f"security_audit_report_linux_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, "w") as report_file:
            report_file.write("\n".join(self.report))

        print(f"Security audit report generated: {report_path}")


if __name__ == "__main__":
    print("Starting Security Audit on Linux...")
    audit = SecurityAuditLinux()
    audit.generate_report()
    print("Audit completed.")
