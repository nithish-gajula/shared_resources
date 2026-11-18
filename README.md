# `shared_resources` — Tester Distribution & Release Artifacts

The dedicated distribution and release repository for external testers, quality assurance (QA) engineers, and security auditors evaluating the Omega runtime architecture.

This repository provides pre-built, production-ready debug APKs and test resources, allowing testers to install and evaluate the latest features without requiring a full local compilation pipeline.

---

## Release Artifacts Catalog

| Artifact | Version | Release Date | Architecture | Key Features / Changelog |
| :--- | :--- | :--- | :--- | :--- |
| [**`app-debug-v1.1.apk`**](file:///home/icps1101/Desktop/Omega-REA/shared_resources/app-debug-v1.1.apk) | **v1.1** | **2026-11-18** | `arm64-v8a` (AArch64) | **Selectable Dual Native Engine Architecture**: Allows choosing between `libomega-timestamp.so` (generated) and `libomega.so` (original reference) in `LauncherActivity`. Includes responsive 360° semicircular radar threat alerts and un-truncated 67,224-byte telemetry frames. |
| [**`app-debug-v1.0.apk`**](file:///home/icps1101/Desktop/Omega-REA/shared_resources/app-debug-v1.0.apk) | **v1.0** | 2026-11-18 | `arm64-v8a` (AArch64) | Baseline production release: Initial decoupled root daemon (`sock64b`) and hardware Canvas overlay (`libomega.so`). |

---

## Tester Prerequisites & Device Compatibility

Before installing and testing the release APKs, verify the following device requirements:

1. **Android Operating System:**
   - Supported versions: **Android 9.0 (Pie / API 28) through Android 14.0 (Upside Down Cake / API 34)**.
   - Target ABI: **64-bit ARM (`arm64-v8a` / AArch64)**. 32-bit devices are not supported.
2. **Superuser (Root) Access:**
   - A rooted Android environment is required to allow the background introspection engine (`sock64b`) to perform kernel `process_vm_readv` (Syscall 270) memory access.
   - Supported root managers:
     - **Magisk** (v24.0+)
     - **KernelSU** (v0.6.0+)
     - **APatch** (v10.7+)
3. **Computer with ADB (Android Debug Bridge):**
   - Required for sideloading APKs, inspecting real-time diagnostics, and capturing test reports.

---

## Environment Setup for Testing

### 🐧 Linux Platform Setup (Ubuntu / Debian / Fedora)

#### 1. Install ADB (Android Debug Bridge) & Git
```bash
sudo apt update
sudo apt install -y adb git
```

#### 2. Configure USB Permissions (udev rules)
```bash
# Add current user to plugdev group
sudo usermod -aG plugdev $USER

# Restart ADB server
adb kill-server
adb start-server
```

#### 3. Enable USB Debugging on Your Android Phone
- Open **Settings** > **About Phone**.
- Tap **Build Number** 7 times to enable **Developer Options**.
- Go to **Settings** > **Developer Options** and enable **USB Debugging**.
- Connect your phone via USB cable and verify detection:
  ```bash
  adb devices
  ```
  *(Accept the "Allow USB debugging?" prompt on your phone screen)*.

---

### 🪟 Windows Platform Setup (Windows 10 / 11)

#### 1. Install ADB (Android Debug Bridge)
- **Option A (Via Windows Package Manager — Quickest):**
  Open PowerShell and run:
  ```powershell
  winget install Google.PlatformTools
  ```
- **Option B (Manual ZIP Download):**
  1. Download the [Android SDK Platform-Tools for Windows](https://dl.google.com/android/repository/platform-tools-latest-windows.zip).
  2. Extract to `C:\platform-tools`.
  3. Add `C:\platform-tools` to your user `Path` environment variable.

#### 2. Install USB OEM Drivers (If Phone is Not Detected)
- If your device does not appear in `adb devices`:
  - Install [Google USB Driver](https://developer.android.com/studio/run/win-usb) or your phone manufacturer's official driver (Samsung Smart Switch, Xiaomi Mi PC Suite, OnePlus USB Drivers).

#### 3. Verify Connection in PowerShell / Command Prompt
```powershell
adb devices
```
Expected output:
```text
List of devices attached
0123456789ABCDEF    device
```

---

## Installation & Deployment Process

### 1. Clone the `shared_resources` Repository

```bash
# Linux
git clone git@github.com:nithish-gajula/shared_resources.git
cd shared_resources

# Windows (PowerShell or Git Bash)
git clone https://github.com/nithish-gajula/shared_resources.git
cd shared_resources
```

### 2. Sideload the Latest Debug APK

```bash
# Linux
adb install -r app-debug-v1.1.apk

# Windows (PowerShell)
adb install -r .\app-debug-v1.1.apk
```

---

## Application Testing & Verification Workflow

Follow these steps to conduct thorough end-to-end testing:

### Step 1: Launch Application & Grant Overlay Permissions
- Open the newly installed **Omega** app from your launcher.
- On first launch, the app prompts for **"Display over other apps"** (Overlay) permission. Enable it in the system settings dialog.

### Step 2: Configure Native Engine & Execution Mode
In the **Launcher** screen:
1. **Select Native Engine Version:**
   - Tap **"Select Native Engine Version"** to open the engine picker dialog:
     - `libomega-timestamp.so (Generated Build)` — Evaluates newly compiled NDK modifications, enhanced radar alerts, and latest canvas rendering code.
     - `libomega.so (Original Reference)` — Evaluates baseline production stability.
2. **Select Execution Mode:**
   - **Local Mode (Recommended for Offline Testing):** Uses bundled encrypted daemon assets (`xalldatq-*.zip`).
   - **Server Mode:** Pulls remote authentication endpoints and server configurations.
3. Tap **Continue**.

### Step 3: Approve Superuser (Root) Request
- When continuing, approve the **Superuser Request** prompt triggered by your root solution (Magisk / KernelSU / APatch).
- The application will automatically unpack the background daemon, initialize the abstract socket IPC bridge, and launch the floating control window.

### Step 4: In-Game Overlay Testing
1. Launch target game (e.g., BGMI, PUBG Mobile Global/KR/VN/TW).
2. Tap the floating **Omega Logo** to open the tactical menu.
3. Test toggles across each category:
   - **ESP View:** Player Box, Skeletons, Snaplines, Distance, Health, and **360° Warning Indicator** (protrudes on screen borders when enemies are behind camera).
   - **Weapon View:** Test visibility of weapon pickups, ammo, and attachments.
   - **Vehicle View:** Test rendering of vehicles (Buggy, UAZ, Dacia, Mirado, etc.).

---

## Capturing Logs & Diagnostic Reports

When reporting anomalies, crashes, or missing items, collect unified logs using the commands below:

### Linux Log Collection
```bash
# Capture full unified diagnostic trace to file
adb logcat -v time -s "Launcher:*" "OmegaNativeLoader:*" "OmegaLog:*" "ESPView:*" "sock64b:*" > test_report_$(date +%Y%m%d_%H%M%S).txt
```

### Windows Log Collection (PowerShell)
```powershell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
adb logcat -v time -s "Launcher:*" "OmegaNativeLoader:*" "OmegaLog:*" "ESPView:*" "sock64b:*" | Out-File -Encoding utf8 "test_report_$timestamp.txt"
```

### External Daemon Log File
In addition to logcat, `sock64b` writes a persistent text log directly to device storage at:
```text
/storage/emulated/0/Omega_log_YYYY-MM-DD_HH-MM-SS.txt
```
You can retrieve this log via ADB:
```bash
adb pull /storage/emulated/0/Omega_log_*.txt .
```

---

## Troubleshooting Guide

| Issue | Root Cause | Solution |
| :--- | :--- | :--- |
| **"Cannot connect to IPC socket"** | Daemon failed to start or root was denied | Verify root access in Magisk/KernelSU. Check that `/data/local/tmp/sock64b` has execute permissions (`chmod 755`). |
| **"Floating overlay does not appear"** | Overlay permission was revoked | Go to Android Settings > Apps > Omega > "Display over other apps" and set to Allowed. |
| **"Items or Vehicles not showing in ESP"** | Entity filter mismatch | Verify item status in [`items_tracker.csv`](file:///home/icps1101/Desktop/Omega-REA/items_tracker.csv) and ensure the corresponding checkbox is enabled in the floating menu. |
| **"App crashes on launch"** | Incompatible ABI or architecture | Ensure testing on a 64-bit device (`arm64-v8a`). 32-bit (`armeabi-v7a`) is unsupported. |
