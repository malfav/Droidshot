import sys
import os
import subprocess
import json
import datetime
import sqlite3
from PyQt5 import QtWidgets, QtCore

# --------------------------
# Filtering Functions to Reduce False Positives
# --------------------------
def filter_file_list(files):
    """Filter out files from common directories that change frequently."""
    ignored_prefixes = ["/sdcard/DCIM", "/sdcard/Download", "/sdcard/Android/data"]
    return [f for f in files if not any(f["path"].startswith(prefix) for prefix in ignored_prefixes)]

def filter_package_list(packages):
    """Filter out common system packages to reduce noise."""
    ignored_prefixes = ["android.", "com.android.", "com.google.android."]
    return [pkg for pkg in packages if not any(pkg.startswith(prefix) for prefix in ignored_prefixes)]

# --------------------------
# Comparison & Formatting Functions
# --------------------------
def compare_file_lists(list1, list2):
    """
    Compare two file lists (each is a list of dicts with keys: path, size, mtime, optionally md5).
    Returns a dict with keys: added, removed, renamed, modified.
    Renamed detection uses MD5 if available, otherwise size and mtime.
    """
    files1 = {item['path']: item for item in list1}
    files2 = {item['path']: item for item in list2}
    
    added_paths = set(files2.keys()) - set(files1.keys())
    removed_paths = set(files1.keys()) - set(files2.keys())
    common_paths = set(files1.keys()).intersection(set(files2.keys()))
    
    added = [files2[path] for path in added_paths]
    removed = [files1[path] for path in removed_paths]
    
    modified = []
    for path in common_paths:
        f1 = files1[path]
        f2 = files2[path]
        if f1['size'] != f2['size'] or f1['mtime'] != f2['mtime']:
            if 'md5' in f1 and 'md5' in f2:
                if f1['md5'] != f2['md5']:
                    modified.append((f1, f2))
            else:
                modified.append((f1, f2))
    
    # Detect renamed files by matching removed and added files.
    renamed = []
    remaining_added = []
    remaining_removed = removed.copy()
    for a in added:
        match_found = None
        for r in remaining_removed:
            if 'md5' in a and 'md5' in r:
                if a['md5'] == r['md5']:
                    match_found = r
                    break
            else:
                if a['size'] == r['size'] and a['mtime'] == r['mtime']:
                    match_found = r
                    break
        if match_found:
            renamed.append((match_found, a))
            remaining_removed.remove(match_found)
        else:
            remaining_added.append(a)
    added = remaining_added
    removed = remaining_removed

    return {
        "added": added,
        "removed": removed,
        "renamed": renamed,
        "modified": modified
    }

def format_diff_results(diff):
    """Format the diff results into structured text output."""
    result = ""
    if diff["added"]:
        result += "=== Files Added ===\n"
        for item in diff["added"]:
            result += f"Path: {item['path']} | Size: {item['size']} | MTime: {item['mtime']}"
            if 'md5' in item:
                result += f" | MD5: {item['md5']}"
            result += "\n"
        result += "\n"
    if diff["removed"]:
        result += "=== Files Removed ===\n"
        for item in diff["removed"]:
            result += f"Path: {item['path']} | Size: {item['size']} | MTime: {item['mtime']}"
            if 'md5' in item:
                result += f" | MD5: {item['md5']}"
            result += "\n"
        result += "\n"
    if diff["renamed"]:
        result += "=== Files Renamed ===\n"
        for old_item, new_item in diff["renamed"]:
            result += (f"From: {old_item['path']} -> To: {new_item['path']} | "
                       f"Size: {old_item['size']} | MTime: {old_item['mtime']}")
            if 'md5' in old_item and 'md5' in new_item:
                result += f" | MD5: {old_item['md5']}"
            result += "\n"
        result += "\n"
    if diff["modified"]:
        result += "=== Files Modified ===\n"
        for old_item, new_item in diff["modified"]:
            result += f"Path: {old_item['path']}\n"
            result += f"  Old -> Size: {old_item['size']} | MTime: {old_item['mtime']}"
            if 'md5' in old_item:
                result += f" | MD5: {old_item['md5']}\n"
            else:
                result += "\n"
            result += f"  New -> Size: {new_item['size']} | MTime: {new_item['mtime']}"
            if 'md5' in new_item:
                result += f" | MD5: {new_item['md5']}\n"
            else:
                result += "\n"
        result += "\n"
    if result == "":
        result = "No differences found."
    return result

# --------------------------
# Main Tool Class
# --------------------------
class SnapshotTool(QtWidgets.QMainWindow):
    def __init__(self):
        super(SnapshotTool, self).__init__()
        self.setWindowTitle("Professional Android Snapshot & Forensic Tool")
        self.resize(1200, 800)
        
        self.db_name = "snapshots.db"
        self.init_db()
        
        self.deep_scan_enabled = False  # Toggle for MD5 deep scan
        
        # For background monitoring, store previous snapshots.
        self.previous_file_snapshot = None
        self.previous_package_snapshot = None
        
        # Setup Tabs: Snapshots, Comparison, Persistence, Dynamic Analysis, Background Monitoring
        self.tab_widget = QtWidgets.QTabWidget()
        self.snapshot_tab = QtWidgets.QWidget()
        self.compare_tab = QtWidgets.QWidget()
        self.persistence_tab = QtWidgets.QWidget()
        self.dynamic_tab = QtWidgets.QWidget()
        self.background_tab = QtWidgets.QWidget()
        
        self.tab_widget.addTab(self.snapshot_tab, "Snapshots")
        self.tab_widget.addTab(self.compare_tab, "Comparison")
        self.tab_widget.addTab(self.persistence_tab, "Persistence Detection")
        self.tab_widget.addTab(self.dynamic_tab, "Dynamic Analysis")
        self.tab_widget.addTab(self.background_tab, "Background Monitoring")
        
        self.setCentralWidget(self.tab_widget)
        
        self.setup_snapshot_tab()
        self.setup_compare_tab()
        self.setup_persistence_tab()
        self.setup_dynamic_tab()
        self.setup_background_tab()
        
        self.load_snapshot_list()
        
        # Background monitoring timer (runs every 60 seconds; adjust interval as needed)
        self.background_timer = QtCore.QTimer(self)
        self.background_timer.timeout.connect(self.run_background_monitoring)
    
    def init_db(self):
        """Initialize the SQLite database to store snapshot data."""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT,
                timestamp TEXT,
                file_list TEXT,
                startup_apps TEXT,
                scheduled_tasks TEXT,
                boot_scripts TEXT
            )
        """)
        conn.commit()
        conn.close()

    # --------------------------
    # Snapshot Tab
    # --------------------------
    def setup_snapshot_tab(self):
        layout = QtWidgets.QVBoxLayout()
        hlayout = QtWidgets.QHBoxLayout()
        self.filename_edit = QtWidgets.QLineEdit()
        self.filename_edit.setPlaceholderText("Enter snapshot name")
        hlayout.addWidget(QtWidgets.QLabel("Snapshot Name:"))
        hlayout.addWidget(self.filename_edit)
        layout.addLayout(hlayout)
        
        self.deep_scan_checkbox = QtWidgets.QCheckBox("Enable Deep Scan (Compute MD5)")
        self.deep_scan_checkbox.stateChanged.connect(self.toggle_deep_scan)
        layout.addWidget(self.deep_scan_checkbox)
        
        self.take_snapshot_btn = QtWidgets.QPushButton("Take Snapshot")
        self.take_snapshot_btn.clicked.connect(self.take_snapshot)
        layout.addWidget(self.take_snapshot_btn)
        
        self.snapshot_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Saved Snapshots:"))
        layout.addWidget(self.snapshot_list)
        
        refresh_btn = QtWidgets.QPushButton("Refresh Snapshot List")
        refresh_btn.clicked.connect(self.load_snapshot_list)
        layout.addWidget(refresh_btn)
        
        self.snapshot_tab.setLayout(layout)

    def toggle_deep_scan(self, state):
        self.deep_scan_enabled = (state == QtCore.Qt.Checked)

    # --------------------------
    # Comparison Tab
    # --------------------------
    def setup_compare_tab(self):
        layout = QtWidgets.QVBoxLayout()
        form_layout = QtWidgets.QHBoxLayout()
        self.snapshot1_combo = QtWidgets.QComboBox()
        self.snapshot2_combo = QtWidgets.QComboBox()
        form_layout.addWidget(QtWidgets.QLabel("Before Snapshot:"))
        form_layout.addWidget(self.snapshot1_combo)
        form_layout.addWidget(QtWidgets.QLabel("After Snapshot:"))
        form_layout.addWidget(self.snapshot2_combo)
        layout.addLayout(form_layout)
        
        self.compare_btn = QtWidgets.QPushButton("Compare Snapshots")
        self.compare_btn.clicked.connect(self.compare_snapshots)
        layout.addWidget(self.compare_btn)
        
        self.diff_viewer = QtWidgets.QTextEdit()
        self.diff_viewer.setReadOnly(True)
        layout.addWidget(QtWidgets.QLabel("Comparison Results:"))
        layout.addWidget(self.diff_viewer)
        
        self.compare_tab.setLayout(layout)

    # --------------------------
    # Persistence Detection Tab
    # --------------------------
    def setup_persistence_tab(self):
        layout = QtWidgets.QVBoxLayout()
        self.persistence_viewer = QtWidgets.QTextEdit()
        self.persistence_viewer.setReadOnly(True)
        check_persistence_btn = QtWidgets.QPushButton("Check Persistence Mechanisms (Latest Snapshot)")
        check_persistence_btn.clicked.connect(self.check_persistence)
        layout.addWidget(check_persistence_btn)
        layout.addWidget(QtWidgets.QLabel("Persistence Detection:"))
        layout.addWidget(self.persistence_viewer)
        self.persistence_tab.setLayout(layout)

    # --------------------------
    # Dynamic Analysis Tab
    # --------------------------
    def setup_dynamic_tab(self):
        layout = QtWidgets.QVBoxLayout()
        
        # Running Processes Group
        proc_group = QtWidgets.QGroupBox("All Running Processes")
        proc_layout = QtWidgets.QVBoxLayout()
        self.process_viewer = QtWidgets.QTextEdit()
        self.process_viewer.setReadOnly(True)
        proc_refresh_btn = QtWidgets.QPushButton("Refresh Processes")
        proc_refresh_btn.clicked.connect(self.refresh_processes)
        proc_layout.addWidget(proc_refresh_btn)
        proc_layout.addWidget(self.process_viewer)
        proc_group.setLayout(proc_layout)
        
        # Installed App Processes Group
        app_proc_group = QtWidgets.QGroupBox("Installed App Processes")
        app_proc_layout = QtWidgets.QVBoxLayout()
        self.app_proc_viewer = QtWidgets.QTextEdit()
        self.app_proc_viewer.setReadOnly(True)
        self.refresh_app_proc_btn = QtWidgets.QPushButton("Refresh Installed App Processes")
        self.refresh_app_proc_btn.clicked.connect(self.refresh_installed_app_processes)
        app_proc_layout.addWidget(self.refresh_app_proc_btn)
        app_proc_layout.addWidget(self.app_proc_viewer)
        app_proc_group.setLayout(app_proc_layout)
        
        # App Network Connections Group
        net_group = QtWidgets.QGroupBox("App Network Connections")
        net_layout = QtWidgets.QVBoxLayout()
        self.net_viewer = QtWidgets.QTextEdit()
        self.net_viewer.setReadOnly(True)
        self.refresh_net_btn = QtWidgets.QPushButton("Refresh App Network Connections")
        self.refresh_net_btn.clicked.connect(self.refresh_app_network_connections)
        net_layout.addWidget(self.refresh_net_btn)
        net_layout.addWidget(self.net_viewer)
        net_group.setLayout(net_layout)
        
        # Advanced Logcat Group with Filter
        log_group = QtWidgets.QGroupBox("Advanced Logcat")
        log_layout = QtWidgets.QVBoxLayout()
        hlayout_log = QtWidgets.QHBoxLayout()
        self.log_filter_edit = QtWidgets.QLineEdit()
        self.log_filter_edit.setPlaceholderText("Enter logcat filter (e.g., package name)")
        self.refresh_log_btn = QtWidgets.QPushButton("Refresh Logcat")
        self.refresh_log_btn.clicked.connect(self.refresh_filtered_logcat)
        hlayout_log.addWidget(self.log_filter_edit)
        hlayout_log.addWidget(self.refresh_log_btn)
        self.log_viewer = QtWidgets.QTextEdit()
        self.log_viewer.setReadOnly(True)
        log_layout.addLayout(hlayout_log)
        log_layout.addWidget(self.log_viewer)
        log_group.setLayout(log_layout)
        
        layout.addWidget(proc_group)
        layout.addWidget(app_proc_group)
        layout.addWidget(net_group)
        layout.addWidget(log_group)
        
        self.dynamic_tab.setLayout(layout)

    # --------------------------
    # Background Monitoring Tab
    # --------------------------
    def setup_background_tab(self):
        layout = QtWidgets.QVBoxLayout()
        
        control_layout = QtWidgets.QHBoxLayout()
        self.start_bg_btn = QtWidgets.QPushButton("Start Background Monitoring")
        self.start_bg_btn.clicked.connect(self.start_background_monitoring)
        self.stop_bg_btn = QtWidgets.QPushButton("Stop Background Monitoring")
        self.stop_bg_btn.clicked.connect(self.stop_background_monitoring)
        control_layout.addWidget(self.start_bg_btn)
        control_layout.addWidget(self.stop_bg_btn)
        layout.addLayout(control_layout)
        
        # File Monitoring Group
        file_group = QtWidgets.QGroupBox("Real-time File Monitoring")
        file_layout = QtWidgets.QVBoxLayout()
        self.file_monitor_viewer = QtWidgets.QTextEdit()
        self.file_monitor_viewer.setReadOnly(True)
        file_layout.addWidget(self.file_monitor_viewer)
        file_group.setLayout(file_layout)
        
        # Package Monitoring Group
        pkg_group = QtWidgets.QGroupBox("Installed Package Monitoring")
        pkg_layout = QtWidgets.QVBoxLayout()
        self.pkg_monitor_viewer = QtWidgets.QTextEdit()
        self.pkg_monitor_viewer.setReadOnly(True)
        pkg_layout.addWidget(self.pkg_monitor_viewer)
        pkg_group.setLayout(pkg_layout)
        
        # API / Logcat Monitoring Group
        api_group = QtWidgets.QGroupBox("API / Logcat Monitoring")
        api_layout = QtWidgets.QVBoxLayout()
        self.api_monitor_viewer = QtWidgets.QTextEdit()
        self.api_monitor_viewer.setReadOnly(True)
        api_layout.addWidget(self.api_monitor_viewer)
        api_group.setLayout(api_layout)
        
        layout.addWidget(file_group)
        layout.addWidget(pkg_group)
        layout.addWidget(api_group)
        
        self.background_tab.setLayout(layout)

    # --------------------------
    # ADB Utility Functions
    # --------------------------
    def run_adb_command(self, command):
        """Run an ADB command and return its output."""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            return f"Error: {e}"

    def is_device_connected(self):
        output = self.run_adb_command("adb devices")
        return any("\tdevice" in line for line in output.splitlines() if "List of devices" not in line)

    # --------------------------
    # File & Snapshot Functions
    # --------------------------
    def get_file_list(self):
        """
        Retrieve a structured file list from /sdcard/ using find and stat.
        Each file entry is a dict with keys: path, size, mtime.
        Optionally compute the MD5 if deep_scan_enabled.
        """
        cmd = 'adb shell "find /sdcard/ -type f -exec stat -c \'%n|%s|%Y\' {} \\;"'
        output = self.run_adb_command(cmd)
        files = []
        for line in output.splitlines():
            try:
                parts = line.split("|")
                if len(parts) >= 3:
                    path = parts[0].strip()
                    size = int(parts[1].strip())
                    mtime = int(parts[2].strip())
                    entry = {"path": path, "size": size, "mtime": mtime}
                    if self.deep_scan_enabled:
                        md5 = self.compute_md5(path)
                        if md5:
                            entry["md5"] = md5
                    files.append(entry)
            except Exception:
                continue
        # Apply file filtering to reduce noise.
        return filter_file_list(files)

    def compute_md5(self, file_path):
        """Compute MD5 for a file on the device using 'adb shell md5sum'."""
        cmd = f'adb shell "md5sum \'{file_path}\'"'
        output = self.run_adb_command(cmd)
        parts = output.split()
        if parts and len(parts) >= 1:
            return parts[0].strip()
        return None

    def get_persistence_data(self):
        """
        Retrieve persistence-related data:
          - Startup Apps (registered for BOOT_COMPLETED)
          - Scheduled Tasks (from dumpsys alarm)
          - Boot Scripts in /data/system/
        """
        startup_cmd = 'adb shell "cmd package query-intent-activities -a android.intent.action.BOOT_COMPLETED"'
        startup_output = self.run_adb_command(startup_cmd)
        startup_apps = [line.strip() for line in startup_output.splitlines() if line.strip()]
        
        scheduled_tasks = self.run_adb_command("adb shell dumpsys alarm")
        
        boot_scripts_output = self.run_adb_command("adb shell ls -la /data/system/")
        boot_scripts = [line for line in boot_scripts_output.splitlines() if line.strip()]
        
        return {
            "startup_apps": startup_apps,
            "scheduled_tasks": scheduled_tasks,
            "boot_scripts": boot_scripts
        }

    def take_snapshot(self):
        if not self.is_device_connected():
            QtWidgets.QMessageBox.warning(self, "ADB Error", "No device connected. Please connect your device via ADB.")
            return
        
        name = self.filename_edit.text().strip()
        if not name:
            QtWidgets.QMessageBox.warning(self, "Error", "Please enter a snapshot name.")
            return

        self.statusBar().showMessage("Taking snapshot...")
        QtWidgets.QApplication.processEvents()

        file_list = self.get_file_list()
        persistence = self.get_persistence_data()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO snapshots (name, timestamp, file_list, startup_apps, scheduled_tasks, boot_scripts)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, timestamp, json.dumps(file_list),
              json.dumps(persistence["startup_apps"]),
              persistence["scheduled_tasks"],
              json.dumps(persistence["boot_scripts"])))
        conn.commit()
        conn.close()

        self.statusBar().showMessage("Snapshot taken successfully!", 3000)
        QtWidgets.QMessageBox.information(self, "Success", "Snapshot taken successfully!")
        self.load_snapshot_list()

    def load_snapshot_list(self):
        self.snapshot_list.clear()
        self.snapshot1_combo.clear()
        self.snapshot2_combo.clear()

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM snapshots")
        snapshots = [row[0] for row in cursor.fetchall()]
        conn.close()

        self.snapshot_list.addItems(snapshots)
        self.snapshot1_combo.addItems(snapshots)
        self.snapshot2_combo.addItems(snapshots)

    def compare_snapshots(self):
        snap1_name = self.snapshot1_combo.currentText()
        snap2_name = self.snapshot2_combo.currentText()
        if not snap1_name or not snap2_name:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select two snapshots to compare.")
            return
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT file_list FROM snapshots WHERE name = ?", (snap1_name,))
        row1 = cursor.fetchone()
        cursor.execute("SELECT file_list FROM snapshots WHERE name = ?", (snap2_name,))
        row2 = cursor.fetchone()
        conn.close()
        if row1 is None or row2 is None:
            QtWidgets.QMessageBox.warning(self, "Error", "One or both snapshots not found.")
            return
        
        try:
            list1 = json.loads(row1[0])
            list2 = json.loads(row2[0])
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error parsing snapshot data: {e}")
            return
        
        diff = compare_file_lists(list1, list2)
        result_text = format_diff_results(diff)
        self.diff_viewer.setPlainText(result_text)

    # --------------------------
    # Persistence Detection
    # --------------------------
    def check_persistence(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT startup_apps, scheduled_tasks, boot_scripts, timestamp 
            FROM snapshots ORDER BY id DESC LIMIT 1
        """)
        row = cursor.fetchone()
        conn.close()
        if not row:
            self.persistence_viewer.setPlainText("No snapshot data available for persistence detection.")
            return

        startup_apps = json.loads(row[0])
        scheduled_tasks = row[1]
        boot_scripts = json.loads(row[2])
        timestamp = row[3]

        persistence_text = f"Snapshot Timestamp: {timestamp}\n\n"
        persistence_text += "=== Startup Apps (BOOT_COMPLETED) ===\n"
        if startup_apps:
            for app in startup_apps:
                persistence_text += f"{app}\n"
        else:
            persistence_text += "No startup apps found.\n"
        
        persistence_text += "\n=== Scheduled Tasks (Alarms) ===\n"
        persistence_text += scheduled_tasks if scheduled_tasks else "No scheduled tasks found.\n"
        
        persistence_text += "\n=== Boot Scripts / Persistence Files (/data/system/) ===\n"
        if boot_scripts:
            for script in boot_scripts:
                persistence_text += f"{script}\n"
        else:
            persistence_text += "No boot scripts or persistence files found.\n"
        
        self.persistence_viewer.setPlainText(persistence_text)

    # --------------------------
    # Dynamic Analysis Functions
    # --------------------------
    def refresh_processes(self):
        output = self.run_adb_command("adb shell ps")
        self.process_viewer.setPlainText(output if output else "No data.")

    def refresh_installed_app_processes(self):
        ps_output = self.run_adb_command("adb shell ps")
        lines = ps_output.splitlines()
        result_lines = []
        installed_pids = set()
        for line in lines:
            parts = line.split()
            if len(parts) < 9:
                continue
            process_name = parts[-1]
            pid = parts[1]
            if '.' in process_name:
                result_lines.append(f"PID: {pid} | Name: {process_name}")
                installed_pids.add(pid)
        display_text = "\n".join(result_lines) if result_lines else "No installed app processes found."
        self.app_proc_viewer.setPlainText(display_text)
        self.installed_app_pids = installed_pids

    def refresh_app_network_connections(self):
        self.refresh_installed_app_processes()
        installed_pids = getattr(self, "installed_app_pids", set())
        net_output = self.run_adb_command("adb shell netstat -p")
        lines = net_output.splitlines()
        filtered_lines = []
        for line in lines:
            parts = line.split()
            if len(parts) < 7:
                continue
            pid_prog = parts[-1]
            if '/' in pid_prog:
                pid = pid_prog.split('/')[0]
                if pid in installed_pids:
                    filtered_lines.append(line)
        display_text = "\n".join(filtered_lines) if filtered_lines else "No network connections found for installed apps."
        self.net_viewer.setPlainText(display_text)

    def refresh_filtered_logcat(self):
        filter_str = self.log_filter_edit.text().strip()
        log_output = self.run_adb_command("adb logcat -d -t 200")
        if filter_str:
            filtered = [line for line in log_output.splitlines() if filter_str in line]
            display_text = "\n".join(filtered)
        else:
            display_text = log_output
        self.log_viewer.setPlainText(display_text)

    # --------------------------
    # Background Monitoring Functions
    # --------------------------
    def get_installed_packages(self):
        """
        Retrieve installed packages using adb shell.
        Returns a list of package strings after filtering common system packages.
        """
        pkg_output = self.run_adb_command("adb shell pm list packages -f")
        packages = []
        for line in pkg_output.splitlines():
            if line.startswith("package:"):
                try:
                    pkg = line.split('=')[-1].strip()
                    packages.append(pkg)
                except Exception:
                    continue
        return filter_package_list(packages)

    def get_api_log(self):
        """
        Retrieve the last 100 logcat lines and filter those that mention "API".
        """
        log_output = self.run_adb_command("adb logcat -d -t 100")
        filtered = [line for line in log_output.splitlines() if "API" in line]
        return "\n".join(filtered)

    def run_background_monitoring(self):
        """Periodically check file system changes, package changes, and API log events with filtering."""
        if not self.is_device_connected():
            self.file_monitor_viewer.setPlainText("No device connected.")
            self.pkg_monitor_viewer.setPlainText("No device connected.")
            self.api_monitor_viewer.setPlainText("No device connected.")
            return

        # FILE MONITORING
        current_files = self.get_file_list()
        if self.previous_file_snapshot is not None:
            diff = compare_file_lists(self.previous_file_snapshot, current_files)
            file_diff_text = format_diff_results(diff)
        else:
            file_diff_text = "Initial file snapshot captured."
        self.file_monitor_viewer.setPlainText(file_diff_text)
        self.previous_file_snapshot = current_files

        # PACKAGE MONITORING
        current_pkgs = self.get_installed_packages()
        if self.previous_package_snapshot is not None:
            added = set(current_pkgs) - set(self.previous_package_snapshot)
            removed = set(self.previous_package_snapshot) - set(current_pkgs)
            pkg_diff_text = ""
            if added:
                pkg_diff_text += "=== Packages Added ===\n" + "\n".join(added) + "\n\n"
            if removed:
                pkg_diff_text += "=== Packages Removed ===\n" + "\n".join(removed) + "\n\n"
            if not pkg_diff_text:
                pkg_diff_text = "No changes in installed packages."
        else:
            pkg_diff_text = "Initial package list captured."
        self.pkg_monitor_viewer.setPlainText(pkg_diff_text)
        self.previous_package_snapshot = current_pkgs

        # API / LOGCAT MONITORING
        api_log = self.get_api_log()
        if not api_log:
            api_log = "No API-related log events detected."
        self.api_monitor_viewer.setPlainText(api_log)

    def start_background_monitoring(self):
        # Run monitoring immediately to show initial output
        self.run_background_monitoring()
        # Start timer: run every 60 seconds (adjust interval as needed)
        self.background_timer.start(60000)
        QtWidgets.QMessageBox.information(self, "Background Monitoring", "Background monitoring started.")

    def stop_background_monitoring(self):
        self.background_timer.stop()
        QtWidgets.QMessageBox.information(self, "Background Monitoring", "Background monitoring stopped.")

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = SnapshotTool()
    window.show()
    sys.exit(app.exec_())
