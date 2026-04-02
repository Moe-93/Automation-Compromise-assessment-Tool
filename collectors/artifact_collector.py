
"""
Artifact Collector Module
Collects forensic artifacts from Windows and Linux systems
Uses native tools and APIs for safe, forensically-sound collection
"""

import os
import sys
import platform
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import zipfile
import json


class ArtifactCollector:
    """Collect forensic artifacts from Windows or Linux systems"""

    def __init__(self, output_dir: str = "collected_artifacts"):
        self.output_dir = output_dir
        self.hostname = platform.node()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.collection_dir = os.path.join(output_dir, f"{self.hostname}_{self.timestamp}")
        self.collected_files = []
        self.errors = []

        # Create collection directory
        os.makedirs(self.collection_dir, exist_ok=True)

    def log_activity(self, message: str, level: str = "INFO"):
        """Log collection activity"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        print(log_entry)

        # Write to log file
        log_file = os.path.join(self.collection_dir, "collection.log")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")

    def collect_windows_artifacts(self, artifacts_list: Optional[List[str]] = None):
        """Collect Windows forensic artifacts"""
        if platform.system() != "Windows":
            self.log_activity("Not running on Windows, skipping Windows collection", "WARNING")
            return False

        self.log_activity("Starting Windows artifact collection...")

        # Define all Windows artifacts
        windows_artifacts = {
            "Prefetch": {
                "path": r"C:\Windows\Prefetch",
                "dest": "Prefetch",
                "type": "directory"
            },
            "ShimCache": {
                "path": r"C:\Windows\AppCompat\Programs\Amcache.hve",
                "alt_path": r"C:\Windows\AppCompat\Programs\RecentFileCache.bcf",
                "dest": "ShimCache",
                "type": "file"
            },
            "AmCache": {
                "path": r"C:\Windows\AppCompat\Programs\Amcache.hve",
                "dest": "AmCache",
                "type": "file"
            },
            "StartupItems": {
                "paths": [
                    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
                    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
                ],
                "dest": "StartupItems",
                "type": "multi_directory"
            },
            "DLLs": {
                "path": r"C:\Windows\System32",
                "dest": "DLLs",
                "type": "directory_listing"
            },
            "HostedServices": {
                "command": "sc query type= service state= all",
                "dest": "HostedServices\services.txt",
                "type": "command"
            },
            "Executables": {
                "paths": [
                    r"C:\Windows\System32",
                    r"C:\Windows\SysWOW64"
                ],
                "dest": "Executables",
                "type": "executable_listing"
            },
            "SecurityWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Security.evtx",
                "dest": "EventLogs\Security.evtx",
                "type": "file"
            },
            "SystemWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\System.evtx",
                "dest": "EventLogs\System.evtx",
                "type": "file"
            },
            "BITSWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-BITS-Client%4Operational.evtx",
                "dest": "EventLogs\BITS_Client.evtx",
                "type": "file"
            },
            "PowerShellOperationalWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
                "dest": "EventLogs\PowerShell_Operational.evtx",
                "type": "file"
            },
            "TaskSchedulerWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx",
                "dest": "EventLogs\TaskScheduler_Operational.evtx",
                "type": "file"
            },
            "LocalTermServerWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx",
                "dest": "EventLogs\TerminalServices_Local.evtx",
                "type": "file"
            },
            "RemoteTermServerWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
                "dest": "EventLogs\TerminalServices_Remote.evtx",
                "type": "file"
            },
            "WindowsPowerShellWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Windows PowerShell.evtx",
                "dest": "EventLogs\Windows_PowerShell.evtx",
                "type": "file"
            },
            "PrintSvcWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-PrintService%4Operational.evtx",
                "dest": "EventLogs\PrintService_Operational.evtx",
                "type": "file"
            },
            "WMIWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\Microsoft-Windows-WMI-Activity%4Operational.evtx",
                "dest": "EventLogs\WMI_Activity.evtx",
                "type": "file"
            },
            "Autoruns": {
                "command": "wmic startup get Caption,Command,Location,User /format:csv",
                "dest": "Autoruns\startup.csv",
                "type": "command"
            },
            "WERLogs": {
                "path": r"C:\ProgramData\Microsoft\Windows\WER",
                "dest": "WERLogs",
                "type": "directory"
            },
            "NamedPipesAudit": {
                "command": r"powershell Get-ChildItem \\.\pipe\\",
                "dest": "NamedPipes\pipes.txt",
                "type": "command"
            },
            "AppShimsAudit": {
                "path": r"C:\Windows\AppCompat\Programs\Amcache.hve",
                "dest": "AppShims",
                "type": "file"
            },
            "GPOScriptsAudit": {
                "paths": [
                    r"C:\Windows\System32\GroupPolicy\\Machine\Scripts",
                    r"C:\Windows\System32\GroupPolicy\User\Scripts"
                ],
                "dest": "GPOScripts",
                "type": "multi_directory"
            },
            "WindowsFirewall": {
                "command": "netsh advfirewall show allprofiles",
                "dest": "Firewall\\firewall_config.txt",
                "type": "command"
            },
            "CCMRUA": {
                "path": r"C:\Windows\\CCM\Logs",
                "dest": "CCMRUA",
                "type": "directory"
            },
            "DefenderWELS": {
                "path": r"C:\Windows\System32\winevt\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
                "dest": "EventLogs\Defender_Operational.evtx",
                "type": "file"
            },
            "CertUtilCache": {
                "command": "certutil -urlcache *",
                "dest": "CertUtil\\urlcache.txt",
                "type": "command"
            },
            "OSInfo": {
                "command": "systeminfo",
                "dest": "OSInfo\\systeminfo.txt",
                "type": "command"
            },
            "MFT": {
                "command": "fsutil fsinfo ntfsinfo C:",
                "dest": "MFT\\ntfsinfo.txt",
                "type": "command"
            },
            "USBSTOR": {
                "registry_path": r"HKLM\SYSTEM\\CurrentControlSet\Enum\USBSTOR",
                "dest": "USBSTOR\\usb_registry.txt",
                "type": "registry"
            },
            "BrowsingHistory": {
                "paths": [
                    os.path.expandvars(r"%LOCALAPPDATA%\\Microsoft\Windows\History"),
                    os.path.expandvars(r"%LOCALAPPDATA%\Google\\Chrome\User Data\Default\History"),
                    os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles")
                ],
                "dest": "BrowserHistory",
                "type": "multi_path"
            },
            "RunningProcesses": {
                "command": "wmic process get Name,ProcessId,CommandLine,ExecutablePath /format:csv",
                "dest": "Processes\\running_processes.csv",
                "type": "command"
            }
        }

        # Filter artifacts if specific list provided
        if artifacts_list:
            artifacts_to_collect = {k: v for k, v in windows_artifacts.items() if k in artifacts_list}
        else:
            artifacts_to_collect = windows_artifacts

        # Collect each artifact
        for artifact_name, artifact_config in artifacts_to_collect.items():
            try:
                self._collect_windows_artifact(artifact_name, artifact_config)
            except Exception as e:
                self.log_activity(f"Error collecting {artifact_name}: {str(e)}", "ERROR")
                self.errors.append(f"{artifact_name}: {str(e)}")

        # Create collection summary
        self._create_collection_summary("Windows")
        return True

    def _collect_windows_artifact(self, name: str, config: Dict):
        """Collect a single Windows artifact"""
        artifact_type = config.get("type", "file")
        dest_path = os.path.join(self.collection_dir, "Windows", config["dest"])

        os.makedirs(os.path.dirname(dest_path) if "." in os.path.basename(dest_path) else dest_path, exist_ok=True)

        if artifact_type == "file":
            source_path = config.get("path")
            if source_path and os.path.exists(source_path):
                shutil.copy2(source_path, dest_path)
                self.collected_files.append(dest_path)
                self.log_activity(f"Collected {name}: {source_path}")
            else:
                alt_path = config.get("alt_path")
                if alt_path and os.path.exists(alt_path):
                    shutil.copy2(alt_path, dest_path)
                    self.collected_files.append(dest_path)
                    self.log_activity(f"Collected {name} (alt): {alt_path}")
                else:
                    self.log_activity(f"Source not found for {name}: {source_path}", "WARNING")

        elif artifact_type == "directory":
            source_path = config.get("path")
            if source_path and os.path.exists(source_path):
                shutil.copytree(source_path, dest_path, dirs_exist_ok=True)
                self.collected_files.append(dest_path)
                self.log_activity(f"Collected directory {name}: {source_path}")
            else:
                self.log_activity(f"Directory not found for {name}: {source_path}", "WARNING")

        elif artifact_type == "command":
            command = config.get("command")
            if command:
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
                    with open(dest_path, "w", encoding="utf-8") as f:
                        f.write(result.stdout)
                        if result.stderr:
                            f.write("\n\nERRORS:\n" + result.stderr)
                    self.collected_files.append(dest_path)
                    self.log_activity(f"Executed command for {name}")
                except Exception as e:
                    self.log_activity(f"Command failed for {name}: {str(e)}", "ERROR")

        elif artifact_type == "registry":
            reg_path = config.get("registry_path")
            if reg_path:
                try:
                    cmd = f'reg query "{reg_path}" /s'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    with open(dest_path, "w", encoding="utf-8") as f:
                        f.write(result.stdout)
                    self.collected_files.append(dest_path)
                    self.log_activity(f"Exported registry for {name}")
                except Exception as e:
                    self.log_activity(f"Registry export failed for {name}: {str(e)}", "ERROR")

        elif artifact_type in ["multi_directory", "multi_path"]:
            paths = config.get("paths", [])
            for i, path in enumerate(paths):
                if os.path.exists(path):
                    item_dest = os.path.join(dest_path, f"item_{i}")
                    try:
                        if os.path.isdir(path):
                            shutil.copytree(path, item_dest, dirs_exist_ok=True)
                        else:
                            os.makedirs(item_dest, exist_ok=True)
                            shutil.copy2(path, item_dest)
                        self.collected_files.append(item_dest)
                        self.log_activity(f"Collected {name} item {i}: {path}")
                    except Exception as e:
                        self.log_activity(f"Failed to collect {name} item {i}: {str(e)}", "WARNING")

        elif artifact_type == "directory_listing":
            source_path = config.get("path")
            if source_path and os.path.exists(source_path):
                try:
                    files = os.listdir(source_path)
                    with open(dest_path + ".txt", "w", encoding="utf-8") as f:
                        for file in files:
                            f.write(file + "\n")
                    self.collected_files.append(dest_path + ".txt")
                    self.log_activity(f"Listed directory contents for {name}")
                except Exception as e:
                    self.log_activity(f"Directory listing failed for {name}: {str(e)}", "ERROR")

        elif artifact_type == "executable_listing":
            paths = config.get("paths", [])
            all_executables = []
            for path in paths:
                if os.path.exists(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.endswith(".exe"):
                                full_path = os.path.join(root, file)
                                all_executables.append(full_path)
            with open(dest_path + ".txt", "w", encoding="utf-8") as f:
                for exe in all_executables:
                    f.write(exe + "\n")
            self.collected_files.append(dest_path + ".txt")
            self.log_activity(f"Listed {len(all_executables)} executables for {name}")

    def collect_linux_artifacts(self, artifacts_list: Optional[List[str]] = None):
        """Collect Linux forensic artifacts"""
        if platform.system() != "Linux":
            self.log_activity("Not running on Linux, skipping Linux collection", "WARNING")
            return False

        self.log_activity("Starting Linux artifact collection...")

        # Define all Linux artifacts
        linux_artifacts = {
            "Yumlog": {
                "paths": ["/var/log/yum.log", "/var/log/dnf.log", "/var/log/dnf.rpm.log"],
                "dest": "Yumlog",
                "type": "files"
            },
            "ShellHistory": {
                "command": "find /home -name '.bash_history' -o -name '.zsh_history' -o -name '.sh_history' 2>/dev/null",
                "dest": "ShellHistory",
                "type": "find_copy"
            },
            "Crontab": {
                "paths": ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"],
                "dest": "Crontab",
                "type": "multi_path"
            },
            "LastUserLogin": {
                "command": "last -a",
                "dest": "LastUserLogin/last.txt",
                "type": "command"
            },
            "AddUser": {
                "paths": ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"],
                "dest": "AddUser",
                "type": "files"
            },
            "SSHLogin": {
                "paths": ["/var/log/auth.log", "/var/log/secure", "/var/log/sshd.log"],
                "dest": "SSHLogin",
                "type": "files"
            },
            "SudoCommands": {
                "command": "cat /var/log/auth.log | grep -i sudo 2>/dev/null || cat /var/log/secure | grep -i sudo 2>/dev/null",
                "dest": "SudoCommands/sudo_usage.txt",
                "type": "command"
            },
            "Netstat": {
                "command": "netstat -tulpn 2>/dev/null || netstat -tulpn",
                "dest": "Netstat/netstat.txt",
                "type": "command"
            },
            "AuthorizedKeys": {
                "command": "find /home -name 'authorized_keys' 2>/dev/null",
                "dest": "AuthorizedKeys",
                "type": "find_copy"
            },
            "KnownHosts": {
                "command": "find /home -name 'known_hosts' 2>/dev/null",
                "dest": "KnownHosts",
                "type": "find_copy"
            },
            "Users": {
                "command": "cat /etc/passwd",
                "dest": "Users/passwd.txt",
                "type": "command"
            },
            "DockerContainers": {
                "command": "docker ps -a 2>/dev/null && docker images 2>/dev/null && docker system info 2>/dev/null",
                "dest": "DockerContainers/docker_info.txt",
                "type": "command"
            },
            "WebShells": {
                "paths": ["/var/log/apache2", "/var/log/httpd", "/var/log/nginx", "/var/www"],
                "dest": "WebShells",
                "type": "multi_path"
            },
            "MalShells": {
                "command": "find /tmp /var/tmp /dev/shm -name '*.sh' -o -name '*.py' -o -name '*.pl' 2>/dev/null",
                "dest": "MalShells",
                "type": "find_copy"
            },
            "TmpListing": {
                "command": "ls -la /tmp /var/tmp /dev/shm",
                "dest": "TmpListing/tmp_listing.txt",
                "type": "command"
            },
            "Systemd": {
                "paths": ["/etc/systemd/system", "/usr/lib/systemd/system", "/run/systemd/system"],
                "dest": "Systemd",
                "type": "multi_path"
            },
            "PreloadCheck": {
                "paths": ["/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d"],
                "dest": "PreloadCheck",
                "type": "multi_path"
            },
            "SyslogEvents": {
                "paths": ["/var/log/syslog", "/var/log/messages", "/var/log/kern.log"],
                "dest": "SyslogEvents",
                "type": "files"
            },
            "SecureEvents": {
                "paths": ["/var/log/secure", "/var/log/auth.log", "/var/log/audit/audit.log"],
                "dest": "SecureEvents",
                "type": "files"
            },
            "OSInfo": {
                "commands": [
                    ("uname -a", "OSInfo/uname.txt"),
                    ("cat /etc/os-release", "OSInfo/os_release.txt"),
                    ("hostnamectl", "OSInfo/hostnamectl.txt"),
                    ("lscpu", "OSInfo/lscpu.txt"),
                    ("free -h", "OSInfo/memory.txt"),
                    ("df -h", "OSInfo/disk.txt"),
                    ("uptime", "OSInfo/uptime.txt"),
                    ("who", "OSInfo/who.txt"),
                    ("w", "OSInfo/w.txt"),
                    ("lastlog", "OSInfo/lastlog.txt")
                ],
                "dest": "OSInfo",
                "type": "multiple_commands"
            }
        }

        # Filter artifacts if specific list provided
        if artifacts_list:
            artifacts_to_collect = {k: v for k, v in linux_artifacts.items() if k in artifacts_list}
        else:
            artifacts_to_collect = linux_artifacts

        # Collect each artifact
        for artifact_name, artifact_config in artifacts_to_collect.items():
            try:
                self._collect_linux_artifact(artifact_name, artifact_config)
            except Exception as e:
                self.log_activity(f"Error collecting {artifact_name}: {str(e)}", "ERROR")
                self.errors.append(f"{artifact_name}: {str(e)}")

        # Create collection summary
        self._create_collection_summary("Linux")
        return True

    def _collect_linux_artifact(self, name: str, config: Dict):
        """Collect a single Linux artifact"""
        artifact_type = config.get("type", "file")
        dest_path = os.path.join(self.collection_dir, "Linux", config["dest"])

        os.makedirs(os.path.dirname(dest_path) if "." in os.path.basename(dest_path) else dest_path, exist_ok=True)

        if artifact_type == "files":
            paths = config.get("paths", [])
            for path in paths:
                if os.path.exists(path):
                    if os.path.isfile(path):
                        shutil.copy2(path, dest_path)
                        self.collected_files.append(dest_path)
                        self.log_activity(f"Collected {name}: {path}")
                    elif os.path.isdir(path):
                        item_dest = os.path.join(dest_path, os.path.basename(path))
                        shutil.copytree(path, item_dest, dirs_exist_ok=True)
                        self.collected_files.append(item_dest)
                        self.log_activity(f"Collected directory {name}: {path}")

        elif artifact_type == "command":
            command = config.get("command")
            if command:
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
                    with open(dest_path, "w", encoding="utf-8") as f:
                        f.write(result.stdout)
                        if result.stderr:
                            f.write("\n\nERRORS:\n" + result.stderr)
                    self.collected_files.append(dest_path)
                    self.log_activity(f"Executed command for {name}")
                except Exception as e:
                    self.log_activity(f"Command failed for {name}: {str(e)}", "ERROR")

        elif artifact_type == "find_copy":
            command = config.get("command")
            if command:
                try:
                    result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
                    files = result.stdout.strip().split("\n")
                    for i, file_path in enumerate(files):
                        if file_path and os.path.exists(file_path):
                            item_dest = os.path.join(dest_path, f"{name}_{i}_{os.path.basename(file_path)}")
                            shutil.copy2(file_path, item_dest)
                            self.collected_files.append(item_dest)
                    self.log_activity(f"Collected {len(files)} files for {name}")
                except Exception as e:
                    self.log_activity(f"Find/Copy failed for {name}: {str(e)}", "ERROR")

        elif artifact_type == "multi_path":
            paths = config.get("paths", [])
            for i, path in enumerate(paths):
                if os.path.exists(path):
                    item_dest = os.path.join(dest_path, f"item_{i}_{os.path.basename(path)}")
                    try:
                        if os.path.isdir(path):
                            shutil.copytree(path, item_dest, dirs_exist_ok=True)
                        else:
                            shutil.copy2(path, item_dest)
                        self.collected_files.append(item_dest)
                        self.log_activity(f"Collected {name} item {i}: {path}")
                    except Exception as e:
                        self.log_activity(f"Failed to collect {name} item {i}: {str(e)}", "WARNING")

        elif artifact_type == "multiple_commands":
            commands = config.get("commands", [])
            for cmd, rel_path in commands:
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                    cmd_dest = os.path.join(self.collection_dir, "Linux", rel_path)
                    os.makedirs(os.path.dirname(cmd_dest), exist_ok=True)
                    with open(cmd_dest, "w", encoding="utf-8") as f:
                        f.write(result.stdout)
                    self.collected_files.append(cmd_dest)
                except Exception as e:
                    self.log_activity(f"Command failed for {name}: {str(e)}", "WARNING")
            self.log_activity(f"Executed {len(commands)} commands for {name}")

    def _create_collection_summary(self, os_type: str):
        """Create a summary file of the collection"""
        summary = {
            "collection_timestamp": self.timestamp,
            "hostname": self.hostname,
            "os_type": os_type,
            "total_files_collected": len(self.collected_files),
            "errors": self.errors,
            "collected_files": self.collected_files,
            "collection_directory": self.collection_dir
        }

        summary_path = os.path.join(self.collection_dir, f"{os_type}_collection_summary.json")
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        self.log_activity(f"Collection complete. Summary saved to {summary_path}")

    def package_collection(self, output_file: Optional[str] = None) -> str:
        """Package all collected artifacts into a zip file"""
        if not output_file:
            output_file = f"{self.hostname}_{self.timestamp}_forensics.zip"

        zip_path = os.path.join(self.output_dir, output_file)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(self.collection_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, self.output_dir)
                    zipf.write(file_path, arcname)

        self.log_activity(f"Collection packaged: {zip_path}")
        return zip_path

    def get_collection_dir(self) -> str:
        """Return the path to the collection directory"""
        return self.collection_dir


def main():
    """Standalone collection mode"""
    import argparse

    parser = argparse.ArgumentParser(description="Collect forensic artifacts")
    parser.add_argument("--os", choices=["windows", "linux", "auto"], default="auto",
                       help="Operating system to collect from")
    parser.add_argument("--output", default="collected_artifacts",
                       help="Output directory for collected artifacts")
    parser.add_argument("--artifacts", nargs="+", default=None,
                       help="Specific artifacts to collect (default: all)")
    parser.add_argument("--package", action="store_true",
                       help="Package collection into zip file")

    args = parser.parse_args()

    # Auto-detect OS
    if args.os == "auto":
        args.os = platform.system().lower()

    collector = ArtifactCollector(output_dir=args.output)

    if args.os == "windows":
        collector.collect_windows_artifacts(args.artifacts)
    elif args.os == "linux":
        collector.collect_linux_artifacts(args.artifacts)
    else:
        print(f"Unsupported OS: {args.os}")
        return 1

    if args.package:
        collector.package_collection()

    return 0


if __name__ == "__main__":
    sys.exit(main())
