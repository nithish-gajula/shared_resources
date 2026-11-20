#!/usr/bin/env python3
"""
sock64b Dynamic Offset Extraction Utility
==========================================
Automatically analyzes versioned AArch64 daemon binaries (sock64b) or password-protected
payload archives (xalldatq-*.zip) to extract all UE4 base pointers, character state offsets,
weapon attributes, and skeletal bone tables.

Outputs ready-to-paste C++ definitions for 'sock64b-project/include/Offsets.h' into
the 'generated_offsets/' directory.
"""

import os
import sys
import struct
import zipfile
import hashlib
import datetime
import argparse
import subprocess
import shutil
from pathlib import Path

DEFAULT_ZIP_PASS = b"d71e173b5e7w5f424kd3a1d1b302029"
TABLE_SIGNATURE = b"\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

def calculate_sha256(data_bytes: bytes) -> str:
    h = hashlib.sha256()
    h.update(data_bytes)
    return h.hexdigest()

def extract_sock64b_from_zip(zip_path: str, password: bytes = DEFAULT_ZIP_PASS) -> bytes:
    """
    Extracts sock64b binary into memory from an encrypted zip archive.
    Supports standard PKZIP encryption, WinZip AES-256 encryption (via 7zz/7z),
    and unzip tool fallback.
    """
    pwd_bytes = password if isinstance(password, bytes) else password.encode("utf-8")
    pwd_str = password.decode("utf-8") if isinstance(password, bytes) else password

    # Attempt 1: Standard Python zipfile (works for standard PKZIP stream cipher, e.g. v4.7)
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.setpassword(pwd_bytes)
            for cand in ["sock64b", "sock64", "sock", "sockb"]:
                if cand in zf.namelist():
                    try:
                        data = zf.read(cand)
                        if len(data) > 1000:
                            return data
                    except Exception:
                        pass
    except Exception:
        pass

    # Attempt 2: 7zz / 7z / 7za (works for AES-256 encrypted zip, e.g. v4.6)
    for cmd in ["7zz", "7z", "7za"]:
        if shutil.which(cmd):
            for cand in ["sock64b", "sock64"]:
                try:
                    out = subprocess.check_output(
                        [cmd, "e", "-so", f"-p{pwd_str}", zip_path, cand],
                        stderr=subprocess.DEVNULL
                    )
                    if len(out) > 1000 and out[:4] == b"\x7fELF":
                        return out
                except Exception:
                    pass

    # Attempt 3: Info-ZIP unzip utility
    if shutil.which("unzip"):
        for cand in ["sock64b", "sock64"]:
            try:
                out = subprocess.check_output(
                    ["unzip", "-P", pwd_str, "-p", zip_path, cand],
                    stderr=subprocess.DEVNULL
                )
                if len(out) > 1000 and out[:4] == b"\x7fELF":
                    return out
            except Exception:
                pass

    raise ValueError(f"Failed to decrypt and extract sock64b from archive: {zip_path}")

def parse_offsets_table(data: bytes, source_name: str) -> dict:
    """Parses .data table offsets from sock64b binary content."""
    pos = data.find(TABLE_SIGNATURE)
    if pos == -1:
        raise ValueError(f"Table signature (0xFF..00) not found in binary: {source_name}")

    table_file_off = pos + len(TABLE_SIGNATURE)

    # 1. Parse 5 regional game base address pairs (16 bytes each: vMatrix, GNames)
    game_keys = [
        ("Global", "com.tencent.ig", "GAME_GLOBAL"),
        ("BGMI", "com.pubg.imobile", "GAME_BGMI"),
        ("Vietnam", "com.vng.pubgmobile", "GAME_VIETNAM"),
        ("Korea", "com.pubg.krmobile", "GAME_KOREA"),
        ("Taiwan", "com.rekoo.pubgm", "GAME_TAIWAN")
    ]
    games = []
    curr = table_file_off
    for label, pkg, edition in game_keys:
        vm, gn = struct.unpack("<QQ", data[curr:curr + 16])
        games.append({
            "label": label,
            "package": pkg,
            "edition": edition,
            "vMatrix": vm,
            "GNames": gn
        })
        curr += 16

    # 2. Parse member offsets QWORDs (35 elements)
    qwords = []
    raw_table_entries = []
    for i in range(35):
        val = struct.unpack("<Q", data[curr:curr + 8])[0]
        qwords.append(val)
        raw_table_entries.append((curr, val))
        curr += 8

    # Check for v4.7+ structural shift (constant 0x08 inserted at index 20)
    has_fname_shift = (len(qwords) > 20 and qwords[20] == 0x08)

    # Extract member offsets based on detected table layout
    offsets = {
        "games": games,
        "table_offset": table_file_off,
        "has_fname_shift": has_fname_shift,
        "raw_entries": raw_table_entries,
        "members": {
            "RootComponent": qwords[0],           # 0x1A8
            "WeaponManager": qwords[1],           # 0x1F0
            "ComponentToWorld": qwords[6],        # 0x4E8
            "BoneArray": qwords[8],               # 0x510
            "CameraCache": qwords[10],            # 0x39C
            "PlayerName": qwords[11],             # 0x960
            "TeamID": qwords[12],                 # 0x998 in v4.6, 0x9A8 in v4.7
            "bIsAI": qwords[13],                  # 0xA59 in v4.6, 0xA69 in v4.7
            "Health": qwords[14],                 # 0xE60 in v4.6, 0xE70 in v4.7
            "HealthMax": qwords[14] + 4,          # Health + 4 (0xE64 in v4.6, 0xE74 in v4.7)
            "bDead": qwords[15],                  # 0xE7C in v4.6, 0xE8C in v4.7
            "CurrentWeapon": qwords[17],          # 0x1840 in v4.6, 0x18B0 in v4.7
            "WeaponID": qwords[5],                # 0x134
            "ShootWeaponEntity": qwords[21] if has_fname_shift else qwords[20], # 0x1380 vs 0x13B8
            "CurBulletNum": qwords[23] if has_fname_shift else qwords[22]       # 0x1E0
        }
    }

    # Extract bone table
    bone_start = 27 if has_fname_shift else 26
    bone_names = [
        "Head", "Neck", "Chest", "Pelvis",
        "L_Shoulder", "R_Shoulder", "L_Elbow", "R_Elbow"
    ]
    bones = {}
    for idx, bname in enumerate(bone_names):
        if bone_start + idx < len(qwords):
            bones[bname] = qwords[bone_start + idx]
    offsets["bones"] = bones

    return offsets

def generate_report_text(offsets: dict, source_name: str, file_size: int, sha256_hash: str) -> str:
    """Formats extracted offsets into human-readable tables and ready-to-paste C++ code."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    members = offsets["members"]
    bones = offsets["bones"]
    games = offsets["games"]
    shift_status = "Modern v4.7+ (0x08 FNameID shift detected)" if offsets["has_fname_shift"] else "Legacy v4.6 layout (Direct ShootWeaponEntity)"

    lines = []
    lines.append("=" * 80)
    lines.append(" sock64b REVERSE ENGINEERING ANALYSIS: EXTRACTED OFFSETS REPORT")
    lines.append("=" * 80)
    lines.append(f"Source Binary / Archive : {source_name}")
    lines.append(f"Analysis Timestamp       : {now_str}")
    lines.append(f"Binary Size              : {file_size:,} bytes")
    lines.append(f"SHA-256 Hash             : {sha256_hash}")
    lines.append(f"Table Architecture       : {shift_status}")
    lines.append(f"Data Table File Offset   : 0x{offsets['table_offset']:X}")
    lines.append("=" * 80)
    lines.append("")

    lines.append("1. REGIONAL GAME BASE ADDRESSES (vMatrix & GNames)")
    lines.append("-" * 80)
    lines.append(f"{'Region / Game Package':<32} | {'Edition Tag':<15} | {'vMatrix Offset':<16} | {'GNames Offset'}")
    lines.append("-" * 80)
    for g in games:
        lines.append(f"{g['package'] + ' (' + g['label'] + ')':<32} | {g['edition']:<15} | 0x{g['vMatrix']:08X}       | 0x{g['GNames']:08X}")
    lines.append("-" * 80)
    lines.append("")

    lines.append("2. CHARACTER STATE & ACTOR OFFSETS (ASTExtraCharacter)")
    lines.append("-" * 80)
    lines.append(f"{'Field / Attribute':<36} | {'Hex Offset':<16} | {'Decimal Value'}")
    lines.append("-" * 80)
    for k in ["TeamID", "bIsAI", "Health", "HealthMax", "bDead", "CurrentWeapon", "PlayerName", "CameraCache", "BoneArray", "ComponentToWorld"]:
        val = members.get(k, 0)
        lines.append(f"ASTExtraCharacter_{k:<18} | 0x{val:06X}         | {val}")
    lines.append("-" * 80)
    lines.append("")

    lines.append("3. WEAPON & EQUIPMENT OFFSETS (ASTExtraWeapon)")
    lines.append("-" * 80)
    lines.append(f"{'Field / Attribute':<36} | {'Hex Offset':<16} | {'Decimal Value'}")
    lines.append("-" * 80)
    for k in ["WeaponEntity", "WeaponID", "CurBulletNum", "WeaponManager"]:
        field_key = "ShootWeaponEntity" if k == "WeaponEntity" else k
        val = members.get(field_key, 0)
        lines.append(f"ASTExtraWeapon_{k:<21} | 0x{val:06X}         | {val}")
    lines.append("-" * 80)
    lines.append("")

    lines.append("4. SKELETAL BONE OFFSETS")
    lines.append("-" * 80)
    lines.append(f"{'Bone Node':<36} | {'Hex Offset':<16} | {'Decimal Value'}")
    lines.append("-" * 80)
    for bname, bval in bones.items():
        lines.append(f"Bone_{bname:<29} | 0x{bval:06X}         | {bval}")
    lines.append("-" * 80)
    lines.append("")

    lines.append("=" * 80)
    lines.append(" READY-TO-PASTE C++ SOURCE FOR sock64b-project/include/Offsets.h")
    lines.append("=" * 80)
    lines.append("")
    lines.append("/**")
    lines.append(f" * Valid UE4 Base Offsets extracted via REA inspection from {source_name}:")
    for g in games:
        lines.append(f" * - {g['label']} ({g['package']}): vMatrix=0x{g['vMatrix']:08X}, GNames=0x{g['GNames']:08X}")
    lines.append(" */")
    lines.append("static const GameOffsets SUPPORTED_GAMES[] = {")
    for g in games:
        lines.append(f'    {{ "{g["package"]}", {g["edition"]}, 0x{g["vMatrix"]:08X}, 0x{g["GNames"]:08X}, 0x{g["vMatrix"]:08X} }},')
    lines.append("};")
    lines.append("")
    lines.append("namespace UE4Offsets {")
    lines.append("    // Player State, Health & Attributes")
    lines.append(f"    constexpr uintptr_t ASTExtraCharacter_TeamID        = 0x{members['TeamID']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraCharacter_bIsAI         = 0x{members['bIsAI']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraCharacter_Health        = 0x{members['Health']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraCharacter_HealthMax     = 0x{members['HealthMax']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraCharacter_bDead         = 0x{members['bDead']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraCharacter_CurrentWeapon = 0x{members['CurrentWeapon']:X};")
    lines.append("")
    lines.append("    // Weapon Structs")
    lines.append(f"    constexpr uintptr_t ASTExtraWeapon_WeaponEntity     = 0x{members['ShootWeaponEntity']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraWeapon_WeaponID         = 0x{members['WeaponID']:X};")
    lines.append(f"    constexpr uintptr_t ASTExtraWeapon_CurBulletNum     = 0x{members['CurBulletNum']:X};")
    lines.append("}")
    lines.append("")
    lines.append("=" * 80)
    lines.append(" END OF REPORT")
    lines.append("=" * 80)

    return "\n".join(lines)

def process_target(target_path: str, output_dir: str, password: bytes = DEFAULT_ZIP_PASS) -> str:
    """Processes a single target (binary or zip), extracts offsets, writes text output."""
    path_obj = Path(target_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Target path not found: {target_path}")

    # Determine binary content and version tag
    if path_obj.suffix.lower() == ".zip":
        print(f"[*] Decrypting and reading sock64b from archive: {path_obj.name}")
        data = extract_sock64b_from_zip(str(path_obj), password)
        version_tag = path_obj.stem.replace("xalldatq-", "").replace("xalldatq", "")
        if not version_tag or version_tag.startswith("-"):
            version_tag = "original"
        else:
            version_tag = version_tag.lstrip("-_")
    else:
        print(f"[*] Reading ELF binary: {path_obj.name}")
        with open(target_path, "rb") as f:
            data = f.read()
        version_tag = path_obj.stem

    file_size = len(data)
    sha256_hash = calculate_sha256(data)

    print(f"    - Extracted binary size : {file_size:,} bytes")
    print(f"    - SHA-256 Checksum      : {sha256_hash}")

    # Parse offsets
    offsets = parse_offsets_table(data, path_obj.name)

    # Format report
    report_text = generate_report_text(offsets, path_obj.name, file_size, sha256_hash)

    # Determine output filename
    os.makedirs(output_dir, exist_ok=True)
    out_filename = f"offsets_{version_tag}.txt"
    out_file_path = os.path.join(output_dir, out_filename)

    with open(out_file_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    print(f"[+] Output written to   : {out_file_path}")
    print("\n" + report_text)
    return out_file_path

def main():
    parser = argparse.ArgumentParser(
        description="sock64b Dynamic Offset Extraction Utility for UE4 & Offsets.h"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to sock64b binary or xalldatq-*.zip archive. If omitted, scans 'original_files/'"
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory to save generated offsets text files (default: ../generated_offsets)"
    )
    parser.add_argument(
        "--password",
        default="d71e173b5e7w5f424kd3a1d1b302029",
        help="Master decryption password for xalldatq zip archives"
    )

    args = parser.parse_args()

    # Determine default paths relative to script location
    script_dir = Path(__file__).resolve().parent
    base_dir = script_dir.parent
    default_original_dir = base_dir / "original_files"
    output_dir = Path(args.output_dir) if args.output_dir else (base_dir / "generated_offsets")
    output_dir.mkdir(parents=True, exist_ok=True)

    pwd = args.password.encode("utf-8")

    if args.target:
        process_target(args.target, str(output_dir), pwd)
    else:
        # Auto-discovery mode: scan original_files
        print("=" * 80)
        print(" sock64b Dynamic Offset Extraction Utility (Batch Auto-Discovery Mode)")
        print(f" Scanning directory: {default_original_dir}")
        print("=" * 80)

        targets = []
        if default_original_dir.exists():
            for f in sorted(default_original_dir.iterdir()):
                if f.suffix.lower() == ".zip" or "sock64b" in f.name.lower():
                    targets.append(str(f))

        if not targets:
            print(f"[!] No archives or sock64b binaries found in: {default_original_dir}")
            print("    Please provide a file directly: python3 extract_offsets.py <file>")
            sys.exit(1)

        print(f"[*] Found {len(targets)} targets to analyze:")
        for t in targets:
            print(f"    - {t}")
        print("")

        for t in targets:
            print("-" * 80)
            process_target(t, str(output_dir), pwd)
            print("-" * 80 + "\n")

    print("[SUCCESS] All offset reports generated successfully!")

if __name__ == "__main__":
    main()
