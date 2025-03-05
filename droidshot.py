import sys
import os
import subprocess
import json
import datetime
import sqlite3
import re
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
    Reduces false positives by ignoring modifications where only mtime differs if no MD5 is available.
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
        if f1['size'] != f2['size']:
            modified.append((f1, f2))
        elif f1['mtime'] != f2['mtime']:
            if 'md5' in f1 and 'md5' in f2:
                if f1['md5'] != f2['md5']:
                    modified.append((f1, f2))
        # Without MD5, ignore mtime-only changes to reduce false positives.
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

def compare_package_lists(list1, list2):
    """
    Compare two package lists.
    Returns a dict with keys: added, removed.
    """
    set1 = set(list1)
    set2 = set(list2)
    added = list(set2 - set1)
    removed = list(set1 - set2)
    return {"added": added, "removed": removed}

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
        self.resize(1400, 900)
        
        self.db_name = "snapshots.db"
        self.init_db()
        
        self.deep_scan_enabled = False  # Toggle for MD5 deep scan
        
        # For background monitoring, store previous snapshots.
        self.previous_file_snapshot = None
        self.previous_package_snapshot = None
        
        # --------------------------
        # Setup Main Tabs
        # --------------------------
        self.tab_widget = QtWidgets.QTabWidget()
        self.snapshot_tab = QtWidgets.QWidget()
        self.compare_tab = QtWidgets.QWidget()
        self.persistence_tab = QtWidgets.QWidget()
        self.dynamic_tab = QtWidgets.QWidget()
        self.background_tab = QtWidgets.QWidget()
        self.inspection_tab = QtWidgets.QWidget()
        self.static_analysis_tab = QtWidgets.QWidget()
        
        self.tab_widget.addTab(self.snapshot_tab, "Snapshots")
        self.tab_widget.addTab(self.compare_tab, "Comparison")
        self.tab_widget.addTab(self.persistence_tab, "Persistence")
        self.tab_widget.addTab(self.dynamic_tab, "Dynamic Analysis")
        self.tab_widget.addTab(self.background_tab, "Background Monitoring")
        self.tab_widget.addTab(self.inspection_tab, "Inspection")
        self.tab_widget.addTab(self.static_analysis_tab, "Static Analysis")
        
        self.setCentralWidget(self.tab_widget)
        
        # --------------------------
        # Setup Each Tab
        # --------------------------
        self.setup_snapshot_tab()
        self.setup_compare_tab()
        self.setup_persistence_tab()
        self.setup_dynamic_tab()
        self.setup_background_tab()
        self.setup_inspection_tab()
        self.setup_static_analysis_tab()
        
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
                packages TEXT,
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

    def load_snapshot_list(self):
        """Load snapshots from the database and populate list and combo boxes with unique IDs and timestamps."""
        self.snapshot_list.clear()
        self.snapshot1_combo.clear()
        self.snapshot2_combo.clear()

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, timestamp FROM snapshots ORDER BY id")
        snapshots = cursor.fetchall()
        conn.close()

        for snap in snapshots:
            snap_id, name, timestamp = snap
            display_text = f"{name} [{timestamp}]"
            self.snapshot_list.addItem(display_text)
            self.snapshot1_combo.addItem(display_text, snap_id)
            self.snapshot2_combo.addItem(display_text, snap_id)

    def compare_snapshots(self):
        before_id = self.snapshot1_combo.currentData()
        after_id = self.snapshot2_combo.currentData()
        if before_id is None or after_id is None:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select two snapshots to compare.")
            return
        if before_id == after_id:
            QtWidgets.QMessageBox.warning(self, "Error", "Please select two different snapshots for comparison.")
            return

        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("SELECT file_list, packages FROM snapshots WHERE id = ?", (before_id,))
        row1 = cursor.fetchone()
        cursor.execute("SELECT file_list, packages FROM snapshots WHERE id = ?", (after_id,))
        row2 = cursor.fetchone()
        conn.close()
        if row1 is None or row2 is None:
            QtWidgets.QMessageBox.warning(self, "Error", "One or both snapshots not found.")
            return
        
        try:
            list1 = json.loads(row1[0])
            list2 = json.loads(row2[0])
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error parsing file snapshot data: {e}")
            return
        
        file_diff = compare_file_lists(list1, list2)
        file_diff_text = format_diff_results(file_diff)
        
        try:
            pkgs1 = json.loads(row1[1])
            pkgs2 = json.loads(row2[1])
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Error", f"Error parsing package snapshot data: {e}")
            return
        
        pkg_diff = compare_package_lists(pkgs1, pkgs2)
        pkg_diff_text = ""
        if pkg_diff["added"]:
            pkg_diff_text += "=== Packages Added ===\n" + "\n".join(pkg_diff["added"]) + "\n\n"
        if pkg_diff["removed"]:
            pkg_diff_text += "=== Packages Removed ===\n" + "\n".join(pkg_diff["removed"]) + "\n\n"
        if not pkg_diff_text:
            pkg_diff_text = "No differences in installed packages."
        
        result_text = "***** File Differences *****\n" + file_diff_text + "\n***** Package Differences *****\n" + pkg_diff_text
        self.diff_viewer.setPlainText(result_text)

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

    def get_persistence_data(self):
        """
        Retrieve persistence-related data:
          - Startup Apps (registered for BOOT_COMPLETED) [filtered to ignore common system packages]
          - Scheduled Tasks (from dumpsys alarm, filtered for app-related entries)
          - Boot Scripts in /data/system/ and /data/local/init.d/ (if available)
        """
        startup_cmd = 'adb shell "cmd package query-intent-activities -a android.intent.action.BOOT_COMPLETED"'
        startup_output = self.run_adb_command(startup_cmd)
        startup_apps = []
        for line in startup_output.splitlines():
            match = re.search(r'ActivityInfo\{(\S+)/', line)
            if match:
                pkg = match.group(1)
                if not any(pkg.startswith(prefix) for prefix in ["android.", "com.android.", "com.google.android."]):
                    startup_apps.append(pkg)
        scheduled_tasks_output = self.run_adb_command("adb shell dumpsys alarm")
        scheduled_tasks = []
        for line in scheduled_tasks_output.splitlines():
            if '.' in line:
                scheduled_tasks.append(line.strip())
        boot_scripts_output = self.run_adb_command("adb shell ls -la /data/system/")
        boot_scripts = [line.strip() for line in boot_scripts_output.splitlines() if line.strip()]
        initd_output = self.run_adb_command("adb shell ls -la /data/local/init.d")
        init_scripts = [line.strip() for line in initd_output.splitlines() if line.strip() and "No such file" not in line]
        boot_scripts.extend(init_scripts)
        return {
            "startup_apps": startup_apps,
            "scheduled_tasks": scheduled_tasks,
            "boot_scripts": boot_scripts
        }

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

        try:
            startup_apps = json.loads(row[0])
        except Exception:
            startup_apps = []
        scheduled_tasks = row[1]
        try:
            boot_scripts = json.loads(row[2])
        except Exception:
            boot_scripts = []
        timestamp = row[3]

        persistence_text = f"Snapshot Timestamp: {timestamp}\n\n"
        persistence_text += "=== Startup Apps (BOOT_COMPLETED) ===\n"
        if startup_apps:
            for app in startup_apps:
                persistence_text += f"• {app}\n"
        else:
            persistence_text += "No non-system startup apps found.\n"
        
        persistence_text += "\n=== Scheduled Tasks (Alarms) ===\n"
        if scheduled_tasks:
            for line in scheduled_tasks.splitlines():
                if line.strip():
                    persistence_text += f"• {line.strip()}\n"
        else:
            persistence_text += "No scheduled tasks found.\n"
        
        persistence_text += "\n=== Boot Scripts / Persistence Files ===\n"
        if boot_scripts:
            for script in boot_scripts:
                persistence_text += f"• {script}\n"
        else:
            persistence_text += "No boot scripts or persistence files found.\n"
        
        self.persistence_viewer.setPlainText(persistence_text)

    # --------------------------
    # Dynamic Analysis Functions
    # --------------------------
    def setup_dynamic_tab(self):
        layout = QtWidgets.QVBoxLayout()
        
        proc_group = QtWidgets.QGroupBox("All Running Processes")
        proc_layout = QtWidgets.QVBoxLayout()
        self.process_viewer = QtWidgets.QTextEdit()
        self.process_viewer.setReadOnly(True)
        proc_refresh_btn = QtWidgets.QPushButton("Refresh Processes")
        proc_refresh_btn.clicked.connect(self.refresh_processes)
        proc_layout.addWidget(proc_refresh_btn)
        proc_layout.addWidget(self.process_viewer)
        proc_group.setLayout(proc_layout)
        
        app_proc_group = QtWidgets.QGroupBox("Installed App Processes")
        app_proc_layout = QtWidgets.QVBoxLayout()
        self.app_proc_viewer = QtWidgets.QTextEdit()
        self.app_proc_viewer.setReadOnly(True)
        self.refresh_app_proc_btn = QtWidgets.QPushButton("Refresh Installed App Processes")
        self.refresh_app_proc_btn.clicked.connect(self.refresh_installed_app_processes)
        app_proc_layout.addWidget(self.refresh_app_proc_btn)
        app_proc_layout.addWidget(self.app_proc_viewer)
        app_proc_group.setLayout(app_proc_layout)
        
        net_group = QtWidgets.QGroupBox("App Network Connections")
        net_layout = QtWidgets.QVBoxLayout()
        self.net_viewer = QtWidgets.QTextEdit()
        self.net_viewer.setReadOnly(True)
        self.refresh_net_btn = QtWidgets.QPushButton("Refresh App Network Connections")
        self.refresh_net_btn.clicked.connect(self.refresh_app_network_connections)
        net_layout.addWidget(self.refresh_net_btn)
        net_layout.addWidget(self.net_viewer)
        net_group.setLayout(net_layout)
        
        log_group = QtWidgets.QGroupBox("Advanced Logcat")
        log_layout = QtWidgets.QVBoxLayout()
        hlayout_log = QtWidgets.QHBoxLayout()
        self.log_filter_edit_dyn = QtWidgets.QLineEdit()
        self.log_filter_edit_dyn.setPlaceholderText("Enter logcat filter (e.g., package name)")
        self.refresh_log_btn_dyn = QtWidgets.QPushButton("Refresh Logcat")
        self.refresh_log_btn_dyn.clicked.connect(self.refresh_filtered_logcat_dyn)
        hlayout_log.addWidget(self.log_filter_edit_dyn)
        hlayout_log.addWidget(self.refresh_log_btn_dyn)
        self.log_viewer_dyn = QtWidgets.QTextEdit()
        self.log_viewer_dyn.setReadOnly(True)
        log_layout.addLayout(hlayout_log)
        log_layout.addWidget(self.log_viewer_dyn)
        log_group.setLayout(log_layout)
        
        layout.addWidget(proc_group)
        layout.addWidget(app_proc_group)
        layout.addWidget(net_group)
        layout.addWidget(log_group)
        
        self.dynamic_tab.setLayout(layout)

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

    def refresh_filtered_logcat_dyn(self):
        filter_str = self.log_filter_edit_dyn.text().strip()
        log_output = self.run_adb_command("adb shell logcat -d -t 200")
        if filter_str:
            filtered = [line for line in log_output.splitlines() if filter_str in line]
            display_text = "\n".join(filtered)
        else:
            display_text = log_output
        self.log_viewer_dyn.setPlainText(display_text)

    # --------------------------
    # Background Monitoring Functions
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
        
        file_group = QtWidgets.QGroupBox("Real-time File Monitoring")
        file_layout = QtWidgets.QVBoxLayout()
        self.file_monitor_viewer = QtWidgets.QTextEdit()
        self.file_monitor_viewer.setReadOnly(True)
        file_layout.addWidget(self.file_monitor_viewer)
        file_group.setLayout(file_layout)
        
        pkg_group = QtWidgets.QGroupBox("Installed Package Monitoring")
        pkg_layout = QtWidgets.QVBoxLayout()
        self.pkg_monitor_viewer = QtWidgets.QTextEdit()
        self.pkg_monitor_viewer.setReadOnly(True)
        pkg_layout.addWidget(self.pkg_monitor_viewer)
        pkg_group.setLayout(pkg_layout)
        
        api_group = QtWidgets.QGroupBox("API / Logcat Monitoring")
        api_layout = QtWidgets.QVBoxLayout()
        self.api_monitor_viewer = QtWidgets.QTextEdit()
        self.api_monitor_viewer.setReadOnly(True)
        api_layout.addWidget(self.api_monitor_viewer)
        api_group.setLayout(api_layout)
        
        sys_group = QtWidgets.QGroupBox("System Status Monitoring")
        sys_layout = QtWidgets.QVBoxLayout()
        self.battery_viewer = QtWidgets.QTextEdit()
        self.battery_viewer.setReadOnly(True)
        self.meminfo_viewer = QtWidgets.QTextEdit()
        self.meminfo_viewer.setReadOnly(True)
        self.top_viewer = QtWidgets.QTextEdit()
        self.top_viewer.setReadOnly(True)
        sys_layout.addWidget(QtWidgets.QLabel("Battery Status:"))
        sys_layout.addWidget(self.battery_viewer)
        sys_layout.addWidget(QtWidgets.QLabel("Memory Info:"))
        sys_layout.addWidget(self.meminfo_viewer)
        sys_layout.addWidget(QtWidgets.QLabel("CPU Usage (Top):"))
        sys_layout.addWidget(self.top_viewer)
        sys_group.setLayout(sys_layout)
        
        layout.addWidget(file_group)
        layout.addWidget(pkg_group)
        layout.addWidget(api_group)
        layout.addWidget(sys_group)
        
        self.background_tab.setLayout(layout)

    def run_background_monitoring(self):
        if not self.is_device_connected():
            self.file_monitor_viewer.setPlainText("No device connected.")
            self.pkg_monitor_viewer.setPlainText("No device connected.")
            self.api_monitor_viewer.setPlainText("No device connected.")
            self.battery_viewer.setPlainText("No device connected.")
            self.meminfo_viewer.setPlainText("No device connected.")
            self.top_viewer.setPlainText("No device connected.")
            return

        current_files = self.get_file_list()
        if self.previous_file_snapshot is not None:
            diff = compare_file_lists(self.previous_file_snapshot, current_files)
            file_diff_text = format_diff_results(diff)
        else:
            file_diff_text = "Initial file snapshot captured."
        self.file_monitor_viewer.setPlainText(file_diff_text)
        self.previous_file_snapshot = current_files

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

        api_log = self.get_api_log()
        if not api_log:
            api_log = "No API-related log events detected."
        self.api_monitor_viewer.setPlainText(api_log)

        battery_status = self.run_adb_command("adb shell dumpsys battery")
        self.battery_viewer.setPlainText(battery_status if battery_status else "No battery data.")
        
        meminfo = self.run_adb_command("adb shell dumpsys meminfo")
        self.meminfo_viewer.setPlainText(meminfo if meminfo else "No memory info.")
        
        top_output = self.run_adb_command("adb shell top -n 1")
        self.top_viewer.setPlainText(top_output if top_output else "No CPU usage data.")

    def start_background_monitoring(self):
        self.run_background_monitoring()
        self.background_timer.start(60000)
        QtWidgets.QMessageBox.information(self, "Background Monitoring", "Background monitoring started.")

    def stop_background_monitoring(self):
        self.background_timer.stop()
        QtWidgets.QMessageBox.information(self, "Background Monitoring", "Background monitoring stopped.")

    # --------------------------
    # Inspection Tab
    # --------------------------
    def setup_inspection_tab(self):
        layout = QtWidgets.QVBoxLayout()
        
        net_group = QtWidgets.QGroupBox("Network Inspection")
        net_layout = QtWidgets.QVBoxLayout()
        self.net_inspect_viewer = QtWidgets.QTextEdit()
        self.net_inspect_viewer.setReadOnly(True)
        net_refresh_btn = QtWidgets.QPushButton("Refresh Network Inspection")
        net_refresh_btn.clicked.connect(self.refresh_inspection_network)
        net_layout.addWidget(net_refresh_btn)
        net_layout.addWidget(self.net_inspect_viewer)
        net_group.setLayout(net_layout)
        
        file_group = QtWidgets.QGroupBox("File Inspection (Created, Deleted, Renamed, Tampered)")
        file_layout = QtWidgets.QVBoxLayout()
        self.file_inspect_viewer = QtWidgets.QTextEdit()
        self.file_inspect_viewer.setReadOnly(True)
        file_refresh_btn = QtWidgets.QPushButton("Refresh File Inspection")
        file_refresh_btn.clicked.connect(self.refresh_inspection_file)
        file_layout.addWidget(file_refresh_btn)
        file_layout.addWidget(self.file_inspect_viewer)
        file_group.setLayout(file_layout)
        
        pkg_group = QtWidgets.QGroupBox("Package Inspection (Installed/Removed/Renamed/Tampered)")
        pkg_layout = QtWidgets.QVBoxLayout()
        self.pkg_inspect_viewer = QtWidgets.QTextEdit()
        self.pkg_inspect_viewer.setReadOnly(True)
        pkg_refresh_btn = QtWidgets.QPushButton("Refresh Package Inspection")
        pkg_refresh_btn.clicked.connect(self.refresh_inspection_package)
        pkg_layout.addWidget(pkg_refresh_btn)
        pkg_layout.addWidget(self.pkg_inspect_viewer)
        pkg_group.setLayout(pkg_layout)
        
        api_group = QtWidgets.QGroupBox("API Inspection (Logcat Filtering)")
        api_layout = QtWidgets.QVBoxLayout()
        hlayout_api = QtWidgets.QHBoxLayout()
        self.api_filter_edit = QtWidgets.QLineEdit()
        self.api_filter_edit.setPlaceholderText("Enter API filter (e.g., method name)")
        api_refresh_btn = QtWidgets.QPushButton("Refresh API Inspection")
        api_refresh_btn.clicked.connect(self.refresh_inspection_api)
        hlayout_api.addWidget(self.api_filter_edit)
        hlayout_api.addWidget(api_refresh_btn)
        self.api_inspect_viewer = QtWidgets.QTextEdit()
        self.api_inspect_viewer.setReadOnly(True)
        api_layout.addLayout(hlayout_api)
        api_layout.addWidget(self.api_inspect_viewer)
        api_group.setLayout(api_layout)
        
        layout.addWidget(net_group)
        layout.addWidget(file_group)
        layout.addWidget(pkg_group)
        layout.addWidget(api_group)
        self.inspection_tab.setLayout(layout)
    
    def refresh_inspection_network(self):
        output = self.run_adb_command("adb shell netstat -p")
        self.net_inspect_viewer.setPlainText(output if output else "No network data.")
    
    def refresh_inspection_file(self):
        current_files = self.get_file_list()
        if self.previous_file_snapshot is not None:
            diff = compare_file_lists(self.previous_file_snapshot, current_files)
            text = format_diff_results(diff)
        else:
            text = "No previous file snapshot available for comparison."
        self.file_inspect_viewer.setPlainText(text)
    
    def refresh_inspection_package(self):
        current_pkgs = self.get_installed_packages()
        if self.previous_package_snapshot is not None:
            diff = compare_package_lists(self.previous_package_snapshot, current_pkgs)
            text = ""
            if diff["added"]:
                text += "=== Packages Added ===\n" + "\n".join(diff["added"]) + "\n\n"
            if diff["removed"]:
                text += "=== Packages Removed ===\n" + "\n".join(diff["removed"]) + "\n\n"
            if text == "":
                text = "No package changes detected."
        else:
            text = "No previous package snapshot available for comparison."
        self.pkg_inspect_viewer.setPlainText(text)
    
    def refresh_inspection_api(self):
        filter_str = self.api_filter_edit.text().strip()
        log_output = self.run_adb_command("adb shell logcat -d -t 200")
        if filter_str:
            filtered = [line for line in log_output.splitlines() if filter_str in line]
            display_text = "\n".join(filtered)
        else:
            display_text = log_output
        self.api_inspect_viewer.setPlainText(display_text)

    # --------------------------
    # Static Analysis Tab
    # --------------------------
    def setup_static_analysis_tab(self):
        layout = QtWidgets.QVBoxLayout()
        self.static_tab_widget = QtWidgets.QTabWidget()
        
        self.services_tab = self.create_static_subtab("Services", self.refresh_services_static)
        self.activities_tab = self.create_static_subtab("Activities", self.refresh_activities_static)
        self.permissions_tab = self.create_static_subtab("Abused Permissions", self.refresh_permissions_static)
        self.providers_tab = self.create_static_subtab("Providers", self.refresh_providers_static)
        self.libraries_tab = self.create_static_subtab("Libraries", self.refresh_libraries_static)
        self.components_tab = self.create_static_subtab("Components", self.refresh_components_static)
        self.sbom_tab = self.create_static_subtab("SBOM", self.refresh_sbom_static)
        self.static_files_tab = self.create_static_subtab("Files", self.refresh_static_files)
        
        self.static_tab_widget.addTab(self.services_tab, "Services")
        self.static_tab_widget.addTab(self.activities_tab, "Activities")
        self.static_tab_widget.addTab(self.permissions_tab, "Abused Permissions")
        self.static_tab_widget.addTab(self.providers_tab, "Providers")
        self.static_tab_widget.addTab(self.libraries_tab, "Libraries")
        self.static_tab_widget.addTab(self.components_tab, "Components")
        self.static_tab_widget.addTab(self.sbom_tab, "SBOM")
        self.static_tab_widget.addTab(self.static_files_tab, "Files")
        
        layout.addWidget(self.static_tab_widget)
        self.static_analysis_tab.setLayout(layout)
    
    def create_static_subtab(self, title, refresh_callback):
        tab = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()
        refresh_btn = QtWidgets.QPushButton(f"Refresh {title}")
        refresh_btn.clicked.connect(refresh_callback)
        text_viewer = QtWidgets.QTextEdit()
        text_viewer.setReadOnly(True)
        layout.addWidget(refresh_btn)
        layout.addWidget(text_viewer)
        tab.setLayout(layout)
        setattr(self, f"{title.lower().replace(' ', '_')}_viewer", text_viewer)
        return tab
    
    def refresh_services_static(self):
        output = self.run_adb_command("adb shell dumpsys activity services")
        self.services_viewer.setPlainText(output if output else "No services data.")
    
    def refresh_activities_static(self):
        output = self.run_adb_command("adb shell dumpsys activity activities")
        self.activities_viewer.setPlainText(output if output else "No activities data.")
    
    def refresh_permissions_static(self):
        output = self.run_adb_command("adb shell dumpsys package")
        filtered = "\n".join([line for line in output.splitlines() if "permission" in line.lower()])
        self.abused_permissions_viewer.setPlainText(filtered if filtered else "No abused permissions detected.")
    
    def refresh_providers_static(self):
        output = self.run_adb_command("adb shell dumpsys package providers")
        self.providers_viewer.setPlainText(output if output else "No providers data.")
    
    def refresh_libraries_static(self):
        output = self.run_adb_command("adb shell pm list libraries")
        self.libraries_viewer.setPlainText(output if output else "No libraries data.")
    
    def refresh_components_static(self):
        output = self.run_adb_command("adb shell dumpsys package")
        self.components_viewer.setPlainText(output if output else "No components data.")
    
    def refresh_sbom_static(self):
        data_app = self.run_adb_command("adb shell ls /data/app")
        system_app = self.run_adb_command("adb shell ls /system/app")
        text = "Data Apps:\n" + data_app + "\n\nSystem Apps:\n" + system_app
        self.sbom_viewer.setPlainText(text if text else "No SBOM data.")
    
    def refresh_static_files(self):
        files = self.get_file_list()
        text = "\n".join([f"Path: {f['path']} | Size: {f['size']} | MTime: {f['mtime']}" for f in files])
        self.files_viewer.setPlainText(text if text else "No files found.")
    
    # --------------------------
    # ADB Utility Functions
    # --------------------------
    def run_adb_command(self, command):
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
        return filter_file_list(files)

    def compute_md5(self, file_path):
        cmd = f'adb shell "md5sum \'{file_path}\'"'
        output = self.run_adb_command(cmd)
        parts = output.split()
        if parts and len(parts) >= 1:
            return parts[0].strip()
        return None

    def get_installed_packages(self):
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
        log_output = self.run_adb_command("adb shell logcat -d -t 100")
        filtered = [line for line in log_output.splitlines() if "API" in line]
        return "\n".join(filtered)

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
        packages = self.get_installed_packages()
        persistence = self.get_persistence_data()
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO snapshots (name, timestamp, file_list, packages, startup_apps, scheduled_tasks, boot_scripts)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (name, timestamp, json.dumps(file_list), json.dumps(packages),
              json.dumps(persistence["startup_apps"]),
              "\n".join(persistence["scheduled_tasks"]),
              json.dumps(persistence["boot_scripts"])))
        conn.commit()
        conn.close()

        self.statusBar().showMessage("Snapshot taken successfully!", 3000)
        QtWidgets.QMessageBox.information(self, "Success", "Snapshot taken successfully!")
        self.load_snapshot_list()

if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = SnapshotTool()
    window.show()
    sys.exit(app.exec_())
