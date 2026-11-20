# Omega-REA Automated Offset Extractor & Reverse Engineering Forensics Utility

## 1. Overview & Purpose
This utility is an automated reverse engineering and static analysis toolchain designed to extract all required memory pointers, actor attributes, weapon structures, and skeletal bone offsets for [`sock64b-project/include/Offsets.h`](file:///home/icps1101/Desktop/Omega-REA/sock64b-project/include/Offsets.h).

The toolchain provides **two independent, complementary extraction workflows**:

1. **Workflow A: Daemon Payload Extraction (`extract_offsets.py`)**:
   - Inspects versioned `sock64b` AArch64 ELF daemon binaries and encrypted `xalldatq-*.zip` asset payloads.
   - Automatically parses internal `.data` offset tables, handles regional game arrays, detects structural layout shifts (such as the v4.7+ `FNameID` 0x08 shift), and formats C++ definitions.
2. **Workflow B: Direct Game Library Extraction (`extract_from_libue4.py`)**:
   - Inspects reconstructed Unreal Engine 4 shared libraries (`libUE4.so` / `libUE4_v4_7.so`) dumped directly from a live game process (`com.pubg.imobile`) using `UE4Dumper` (via Linux Syscall 270 `process_vm_readv`).
   - Completely removes dependency on third-party daemon releases by extracting `GNames`, `GWorld` / `vMatrix`, character state (`TeamID`, `bIsAI`, `Health`, `HealthMax`, `bDead`, `CurrentWeapon`), and weapon structs directly from Unreal Engine reflection tables and machine code.

---

## 2. Directory Structure

```text
shared_resources/offset_extractor/
├── original_files/              # Reference encrypted zip archives & baselines (IMMUTABLE reference baselines)
│   ├── xalldatq-v4_6.zip        # v4.6 Reference payload (WinZip AES-256 encrypted, read-only)
│   └── xalldatq-v4_7.zip        # v4.7 Reference payload (PKZIP stream cipher encrypted, read-only)
├── generated_offsets/           # Auto-generated formatted offset reports & C++ snippets
│   ├── offsets_v4_6.txt         # Extracted offsets from v4.6 daemon payload
│   ├── offsets_v4_7.txt         # Extracted offsets from v4.7 daemon payload
│   └── offsets_libUE4_v4_7.txt  # Extracted offsets directly from reconstructed libUE4_v4_7.so
├── script/                      # Extraction engine and automation runners
│   ├── extract_offsets.py       # Python 3 reverse engineering engine for sock64b / xalldatq
│   ├── extract_from_libue4.py   # Python 3 direct extraction engine for libUE4.so binaries
│   └── run.sh                   # Unified executable shell runner wrapper
└── README.md                    # System setup, forensic notes & usage guide
```

> [!IMPORTANT]
> **Strict Immutability Policy**: Files inside `original_files/` and `Originals/` (`Originals/libUE4_v4_7.so`, etc.) serve as ground-truth reference baselines. They can be accessed freely for references, pattern extraction, or static inspection, but **must never be modified, renamed, deleted, or overwritten**.

---

## 3. System Requirements & Setup

### Prerequisites
1. **Linux OS / Android Host / WSL2** (Tested on Ubuntu 20.04/22.04/24.04 LTS).
2. **Python 3.6+** (Standard library only; zero external pip dependencies required).
3. **7-Zip (`7zz` or `p7zip`)**: Required for decrypting legacy archives using WinZip AES-256 (e.g., `xalldatq-v4_6.zip`).

### Installation Commands (Debian / Ubuntu)
```bash
sudo apt-get update
sudo apt-get install -y python3 p7zip-full unzip
```

---

## 4. How to Use

### 4.1 Batch Auto-Discovery Mode (Recommended)
Automatically scans `original_files/` and `Originals/`, running both extraction engines across all daemon archives and reconstructed `libUE4.so` libraries:

```bash
cd shared_resources/offset_extractor/script
./run.sh
```

### 4.2 Single Target Extraction

#### Option 1: Direct Extraction from Reconstructed `libUE4.so`
Extract all offsets directly from the game engine library (e.g. `Originals/libUE4_v4_7.so`):

```bash
cd shared_resources/offset_extractor/script
./run.sh /home/icps1101/Desktop/Omega-REA/Originals/libUE4_v4_7.so
```
*or directly with Python:*
```bash
python3 extract_from_libue4.py /home/icps1101/Desktop/Omega-REA/Originals/libUE4_v4_7.so
```

#### Option 2: Extraction from Encrypted Daemon Payloads (`xalldatq-*.zip`)
```bash
cd shared_resources/offset_extractor/script
./run.sh ../original_files/xalldatq-v4_7.zip
```

#### Option 3: Extraction from Standalone `sock64b` Executable
```bash
cd shared_resources/offset_extractor/script
./run.sh /path/to/sock64b
```

---

## 5. Workflow for Future Game Releases (Direct Game Extraction)

When a new game version is released (e.g. **v4.8+**) and before any third-party `sock64b` daemon update is published, you can extract offsets directly from your connected device:

1. **Dump `libUE4.so` using `UE4Dumper`:**
   Connect rooted device via USB and run fast memory dump:
   ```bash
   adb shell su -c "/data/local/tmp/ue4dumper64 --package com.pubg.imobile --lib --fast --output /data/local/tmp"
   adb pull /data/local/tmp/libUE4.so Originals/libUE4_v4_8.so
   ```

2. **Execute Direct Extractor:**
   ```bash
   cd shared_resources/offset_extractor/script
   ./run.sh /home/icps1101/Desktop/Omega-REA/Originals/libUE4_v4_8.so
   ```

3. **Inspect Output & Update `Offsets.h`:**
   Open `generated_offsets/offsets_libUE4_v4_8.txt` and copy the generated C++ definitions directly into [`sock64b-project/include/Offsets.h`](file:///home/icps1101/Desktop/Omega-REA/sock64b-project/include/Offsets.h).

4. **Recompile Daemon:**
   ```bash
   cd sock64b-project
   ./build.sh
   make pack
   ```

---

## 6. Technical Mechanisms & Forensic Analysis

### 6.1 `libUE4.so` Direct Extraction Mechanics (`extract_from_libue4.py`)

1. **GNames Static Resolution**:
   - In Unreal Engine 4.23+, `GNames` is accessed during name lookup in `FNamePool::Init` or `InitNameHash`.
   - The engine code references the UTF-16 diagnostic string `"Wait For Game"` via `ADRP X1, page` and `ADD X1, X1, #offset`.
   - Immediately preceding this instruction is the global `GNames` load: `ADRP X8, page` and `LDR X0, [X8, #offset]`.
   - The script resolves this cross-reference deterministically, yielding `GNames = 0x0EDDC120`.

2. **GWorld & ViewMatrix Resolution**:
   - Global engine instances are initialized behind a thread-safe singleton guard pattern (`ldarb w8, [x8]` followed by `tbz w8, #0`).
   - The init guard is located at `0x0F35CE78` (`1` = initialized).
   - Immediately preceding the guard at `0x0F35CE70` is the canonical live pointer to `UWorld` (`0x72e4ca5440`), with the default camera FOV (`90.0f` / `0x42B40000`) stored at `0x0F35CE58`.

3. **Reflection Property Resolution**:
   - Unreal Engine stores `UProperty` / `FProperty` reflection metadata structs in `.rodata` / `.data`:
     - `TeamID` (`0x9A8`): Resolved from `ASTExtraCharacter` reflection table at `0x1324800+` (cross-referenced by 264 distinct AArch64 `LDR Wt, [Xn, #0x9a8]` instructions in `.text`).
     - `bIsAI` (`0xA69`): Resolved from `UBoolProperty` metadata (`BaseOffset = 0x0A40`, bitfield offset `+0x29` -> `0xA69`).
     - `Health` (`0xE70`) & `HealthMax` (`0xE74`): Resolved from character damage reflection structs and cross-referenced by 183 distinct `LDR St, [Xn, #0xe70]` single-precision float instructions.
     - `bDead` (`0xE8C`): Verified via 80 distinct `LDRB Wt, [Xn, #0xe8c]` boolean load instructions.
     - `CurrentWeapon` (`0x18B0`): Verified via 25 distinct `LDR Xt, [Xn, #0x18b0]` 64-bit pointer loads.
     - `ShootWeaponEntity` (`0x13B8`): Resolved from weapon reflection table at `0x98be90` (base `0x1000 + 0x3B8 = 0x13B8`), verified via 331 distinct 64-bit load instructions.
     - `WeaponID` (`0x134`) & `CurBulletNum` (`0x1E0`): Verified via 487 and 463 distinct 32-bit immediate loads in weapon logic.

### 6.2 `sock64b` Payload Extraction Mechanics (`extract_offsets.py`)

1. **Table Sentinel Signature:**
   The daemon stores its UE4 offset table in `.data` preceded by an 8-byte sentinel `0xFFFFFFFFFFFFFFFF` followed by 16 null bytes (`0x00`).
2. **Regional Base Pointer Table:**
   Slots at `+0x18` index regional base addresses for Global, BGMI, Vietnam, Korea, and Taiwan.
3. **Layout Shift Auto-Detection:**
   - **v4.6 Layout:** Slot 20 contains `0x1380` (`ShootWeaponEntity`).
   - **v4.7+ Layout:** Slot 20 contains `0x08` (`FNameID` shift), shifting subsequent weapon and bone slots by `+0x08` bytes.
4. **Decryption Key:**
   All daemon zip archives use the master payload passphrase:
   `d71e173b5e7w5f424kd3a1d1b302029`
