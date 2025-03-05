![Droidshot](https://github.com/malfav/Droidshot/blob/5d74f9dcdd152034123f1b030e108a264a77f62f/scr.png)Welcome to the Droidshot wiki!

# Features & Capabilities 

## Comprehensive Snapshot & Forensic Collection
* File System Snapshot:
* Captures a detailed file list from the device's storage (typically from /sdcard/), including file sizes, modification times, and optionally MD5 hashes for deep scanning.

## Package Listing:
* Retrieves a filtered list of installed packages to exclude common system apps, enabling forensic analysis of application changes.

## Persistence Mechanisms:
* Gathers data on startup apps (registered for BOOT_COMPLETED), scheduled tasks (via alarm dumpsys), and boot scripts from both /data/system/ and /data/local/init.d/.

## SQLite Integration:
* Stores snapshots (files, packages, persistence data) in an internal database for historical comparison and analysis.

## Advanced Comparison & Analysis
* File Comparison:
* Compares snapshots to detect:

## Added, removed, modified, or renamed files.
* Uses MD5 hashes (when available) to reduce false positives.
* Package Comparison:
* Identifies differences in the list of installed packages (applications added or removed).

## Combined Results Display:
* Presents detailed comparison reports that combine both file and package differences, ensuring changes like APK installations are clearly highlighted.

## Dynamic & Background Monitoring
* Real-time Process Inspection:
* Displays all running processes and filters out installed app processes based on naming conventions.

## Network & Logcat Analysis:
* Monitors network connections of installed apps and provides advanced logcat filtering capabilities for API-related events.

## System Status Monitoring:
* Captures live system metrics such as battery status, memory usage, and CPU usage (via the top command).

## ## Automated Background Monitoring:
* Uses a timer-based system to periodically re-capture snapshots and compare them, alerting you to any changes in files, packages, or system status.

## Inspection & Static Analysis Capabilities
Inspection Tab:
* Provides dedicated views for:
* Network Inspection: Detailed real-time network connection information.
* File Inspection: Comparison of file changes (created, deleted, modified, or renamed).
* Package Inspection: Detection of application changes (installations, removals, or tampering).
* API Inspection: Filtered logcat outputs to monitor API invocations and usage.
## Static Analysis Tab:
* Offers multiple sub-tabs for:
* Services: Analyzes running services.
* Activities: Reviews active and dormant activities.
* Abused Permissions: Identifies unusual or potentially dangerous permission usage.
* Providers: Lists content providers and related data.
* Libraries: Displays information about used libraries.
* Components: Reviews various app components.
* SBOM (Software Bill Of Materials): Provides a high-level view of installed applications.
* Files: Analyzes static file structures.
* Robust Filtering & User Experience
* Minimized False Positives:
* Built-in filtering functions help ignore common “noisy” directories and system packages, ensuring that the results are relevant and actionable.

## User-friendly GUI:
* The PyQt-based interface organizes all functions into clear, distinct tabs, making it easy for both novice and experienced analysts to navigate and use the tool effectively.

## Extensibility:
* The modular design allows for further enhancement and customization to meet evolving forensic and dynamic analysis needs.

