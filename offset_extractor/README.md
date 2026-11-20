# sock64b Automated Offset Extractor & Firmware Forensics Utility

## 1. Overview & Purpose
This utility is an automated reverse engineering and static analysis tool designed to inspect `sock64b` AArch64 ELF daemon binaries and encrypted `xalldatq-*.zip` asset payloads.

When game updates occur (e.g., transition from **v4.6** to **v4.7**, and upcoming **v4.8+** releases), regional Unreal Engine 4 memory pointers, actor structure offsets, weapon attributes, and bone matrices shift in memory. This tool automatically parses the internal `.data` offset tables of the daemon, detects structural layout shifts, and outputs comprehensive analysis reports and ready-to-paste C++ code for updating [`sock64b-project/include/Offsets.h`](file:///home/icps1101/Desktop/Omega-REA/sock64b-project/include/Offsets.h).

---

## 2. Directory Structure

```text
shared_resources/offset_extractor/
├── original_files/          # Reference encrypted zip archives and raw sock64b binaries
│   ├── xalldatq-v4_6.zip    # v4.6 Reference payload (WinZip AES-256 encrypted)
│   └── xalldatq-v4_7.zip    # v4.7 Reference payload (PKZIP stream cipher encrypted)
├── generated_offsets/       # Auto-generated formatted offset reports & C++ snippets
│   ├── offsets_v4_6.txt     # Extracted offsets for v4.6
│   └── offsets_v4_7.txt     # Extracted offsets for v4.7
├── script/                  # Extraction engine and automation runners
│   ├── extract_offsets.py   # Python 3 reverse engineering & pattern discovery engine
│   └── run.sh               # Executable shell runner wrapper
└── README.md                # System setup, forensic notes & usage guide
```

---

## 3. System Requirements & Setup

### Prerequisites
1. **Linux OS / Android Host / WSL2** (Tested on Ubuntu 20.04/22.04/24.04 LTS).
2. **Python 3.6+** (Standard library only; no external pip dependencies required).
3. **7-Zip (`7zz` or `p7zip`)**: Required for decrypting legacy archives using WinZip AES-256 (e.g., `xalldatq-v4_6.zip`).

### Installation Commands (Debian / Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y python3 p7zip-full unzip
```

*(Note: If `7zz` or `7z` is not installed, the tool gracefully falls back to native Python `zipfile` for standard PKZIP archives such as `xalldatq-v4_7.zip` and Info-ZIP `unzip` if available).*

---

## 4. How to Use

### 4.1 Batch Auto-Discovery Mode (Recommended)
Automatically scans the `original_files/` directory, extracts each archive or binary, and generates corresponding `.txt` reports in `generated_offsets/`:

```bash
cd shared_resources/offset_extractor/script
./run.sh
```
*or directly with Python:*
```bash
python3 extract_offsets.py
```

### 4.2 Single Target Mode (Specific Archive or Binary)
Analyze a specific zip file or standalone ELF binary:

```bash
cd shared_resources/offset_extractor/script

# Target a specific encrypted zip archive:
./run.sh ../original_files/xalldatq-v4_7.zip

# Target a standalone extracted sock64b binary:
./run.sh /path/to/sock64b
```

---

## 5. Workflow for Future Game Releases (e.g., Updating to v4.8)

When a new game version is released and a new daemon payload (`xalldatq-v4_8.zip` or raw `sock64b`) becomes available:

1. **Place the New Asset:**
   Copy the new file into `shared_resources/offset_extractor/original_files/`:
   ```bash
   cp /path/to/new/xalldatq-v4_8.zip shared_resources/offset_extractor/original_files/
   ```

2. **Execute the Extractor:**
   ```bash
   cd shared_resources/offset_extractor/script
   ./run.sh
   ```

3. **Inspect Generated Report:**
   Open the newly generated report in `shared_resources/offset_extractor/generated_offsets/offsets_v4_8.txt`.

4. **Update `sock64b-project/include/Offsets.h`:**
   Copy the generated `SUPPORTED_GAMES` table and `namespace UE4Offsets` block directly into [`sock64b-project/include/Offsets.h`](file:///home/icps1101/Desktop/Omega-REA/sock64b-project/include/Offsets.h).

5. **Recompile & Package:**
   ```bash
   cd sock64b-project
   ./build.sh
   make pack
   ```

---

## 6. Reverse Engineering & Binary Layout Forensics

The extraction engine analyzes the binary via pattern recognition and table alignment:

1. **Table Sentinel Signature:**
   The daemon stores its UE4 offset table in the `.data` section preceded by an 8-byte sentinel `0xFFFFFFFFFFFFFFFF` (`\xff\xff\xff\xff\xff\xff\xff\xff`) followed by 16 null bytes (`0x00`).
2. **Regional Base Pointer Table:**
   Located immediately after the sentinel table header at offset `+0x18`:
   - Slot 0: `com.tencent.ig` (Global)
   - Slot 1: `com.pubg.imobile` (BGMI)
   - Slot 2: `com.vng.pubgmobile` (Vietnam)
   - Slot 3: `com.pubg.krmobile` (Korea)
   - Slot 4: `com.rekoo.pubgm` (Taiwan)
3. **Layout Shift Auto-Detection:**
   - **v4.6 Layout:** Slot 20 contains `0x1380` (`ShootWeaponEntity`), followed immediately by weapon IDs and bone tables.
   - **v4.7+ Layout:** Slot 20 contains `0x08` (an `FNameID` component offset), shifting all downstream weapon and bone table entries by `+0x08` bytes (+1 QWORD slot).
4. **Decryption Key:**
   All archives in the project use the master payload passphrase:
   `d71e173b5e7w5f424kd3a1d1b302029`
