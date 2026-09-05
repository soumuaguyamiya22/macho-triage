#!/usr/bin/env python3
"""
macho-triage - quick static triage for a macOS Mach-O binary.

Pulls the things you want to know before trusting a dropped Mach-O, without
running it: the header (arch, type, flags), the dylibs it links, whether it
carries a code signature (and whether that signature is ad-hoc), its rpaths,
entry point and minimum OS, plus any suspicious strings / embedded URLs / IPs.

Everything is static - the file is read once as bytes and parsed with struct.
Nothing is ever executed, so it's safe to point at a sample you don't trust.

Handles fat / universal binaries by walking each slice.

Usage:
    python3 macho_triage.py /path/to/binary
    python3 macho_triage.py /path/to/binary --json > report.json
"""

import argparse
import hashlib
import json
import re
import struct
import sys
from collections import OrderedDict

# First four bytes -> (struct endianness prefix, pointer width in bits).
# Mach-O stores the rest of the header in the byte order its magic implies.
MACH_MAGICS = {
    b"\xce\xfa\xed\xfe": ("<", 32),   # MH_MAGIC     (little-endian)
    b"\xfe\xed\xfa\xce": (">", 32),   # MH_MAGIC     (big-endian)
    b"\xcf\xfa\xed\xfe": ("<", 64),   # MH_MAGIC_64  (little-endian)
    b"\xfe\xed\xfa\xcf": (">", 64),   # MH_MAGIC_64  (big-endian)
}
# Fat headers are always big-endian on disk. (0xcafebabe also collides with a
# Java .class file; we validate each slice's own magic before trusting it.)
FAT_MAGICS = {b"\xca\xfe\xba\xbe": 32, b"\xca\xfe\xba\xbf": 64}

CPU_ARCH_ABI64 = 0x01000000
CPU_TYPES = {
    7: "x86",
    7 | CPU_ARCH_ABI64: "x86_64",
    12: "arm",
    12 | CPU_ARCH_ABI64: "arm64",
    18: "ppc",
    18 | CPU_ARCH_ABI64: "ppc64",
}

FILETYPES = {
    0x1: "MH_OBJECT", 0x2: "MH_EXECUTE", 0x3: "MH_FVMLIB", 0x4: "MH_CORE",
    0x5: "MH_PRELOAD", 0x6: "MH_DYLIB", 0x7: "MH_DYLINKER", 0x8: "MH_BUNDLE",
    0x9: "MH_DYLIB_STUB", 0xA: "MH_DSYM", 0xB: "MH_KEXT_BUNDLE",
}

# Header flags (MH_*) worth surfacing for a triage / hardening read.
MH_PIE = 0x200000
MH_ALLOW_STACK_EXECUTION = 0x20000
HEADER_FLAGS = [
    (0x1, "NOUNDEFS"), (0x80, "TWOLEVEL"), (0x20000, "ALLOW_STACK_EXECUTION"),
    (0x200000, "PIE"), (0x800000, "WEAK_DEFINES"), (0x1000000, "NO_HEAP_EXECUTION"),
    (0x2000000, "APP_EXTENSION_SAFE"),
]

LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x1
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_DYLINKER = 0xE
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_CODE_SIGNATURE = 0x1D
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_MAIN = 0x28 | LC_REQ_DYLD
LC_UNIXTHREAD = 0x5
LC_UUID = 0x1B
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_BUILD_VERSION = 0x32

DYLIB_CMDS = {
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_ID_DYLIB: "LC_ID_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
}
VERSION_MIN_PLATFORM = {
    LC_VERSION_MIN_MACOSX: "macOS", LC_VERSION_MIN_IPHONEOS: "iOS",
    LC_VERSION_MIN_TVOS: "tvOS", LC_VERSION_MIN_WATCHOS: "watchOS",
}
BUILD_PLATFORMS = {
    1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS",
    6: "Mac Catalyst", 7: "iOS Simulator", 8: "tvOS Simulator",
    9: "watchOS Simulator", 10: "DriverKit", 11: "visionOS",
    12: "visionOS Simulator",
}

# Code Signing blob magics (always big-endian on disk).
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CS_ADHOC = 0x2                # CodeDirectory flag: signed with no identity

# Substrings that are worth a second look in a dropped binary. Matched against
# the raw bytes of each slice - a dumb substring pass is enough for triage and
# needs no symbol-table parsing.
SUSPICIOUS_STRINGS = [
    (b"NSTask", "spawns child processes (NSTask)"),
    (b"posix_spawn", "spawns processes (posix_spawn)"),
    (b"osascript", "runs AppleScript (osascript) - UI scripting / persistence"),
    (b"/bin/sh", "references the shell"),
    (b"/bin/bash", "references bash"),
    (b"/bin/zsh", "references zsh"),
    (b"popen", "runs a command via popen()"),
    (b"curl ", "shells out to curl (download / exfil)"),
    (b"SecKeychain", "Keychain Services (credential access)"),
    (b"SecItemCopyMatching", "Keychain item lookup (credential access)"),
    (b"kSecClassGenericPassword", "reads generic-password keychain items"),
    (b"LaunchAgents", "references LaunchAgents (launchd persistence)"),
    (b"LaunchDaemons", "references LaunchDaemons (launchd persistence)"),
    (b"com.apple.quarantine", "touches the quarantine xattr (Gatekeeper handling)"),
    (b"CGEventPost", "synthesizes input events (automation / injection)"),
    (b"CGWindowListCreateImage", "screen-capture API"),
]

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def file_hashes(path):
    md5, sha256, size = hashlib.md5(), hashlib.sha256(), 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            md5.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
    return md5.hexdigest(), sha256.hexdigest(), size


def arch_name(cputype, cpusubtype):
    name = CPU_TYPES.get(cputype, "0x%08x" % (cputype & 0xFFFFFFFF))
    # arm64e carries pointer-authentication; it's CPU_SUBTYPE_ARM64E (2).
    if cputype == (12 | CPU_ARCH_ABI64) and (cpusubtype & 0x00FFFFFF) == 2:
        return "arm64e"
    return name


def decode_version(v):
    """X.Y.Z packed into nibbles: xxxx.yy.zz."""
    return "%d.%d.%d" % ((v >> 16) & 0xFFFF, (v >> 8) & 0xFF, v & 0xFF)


def lc_string(buf, str_offset):
    """Read a Mach-O lc_str: an offset, within the command, to a C string."""
    if str_offset < 0 or str_offset >= len(buf):
        return None
    s = buf[str_offset:]
    nul = s.find(b"\x00")
    if nul >= 0:
        s = s[:nul]
    return s.decode("utf-8", "replace")


def parse_code_signature(data, cs_abs):
    """Peek at the embedded signature so we can tell ad-hoc from identity-signed.

    We do not verify anything - no CDHash recompute, no certificate chain, no
    notarization check. Presence of the blob means a signature is attached; the
    CodeDirectory's flags tell us whether it was signed with a real identity or
    ad-hoc (the self-signature a locally built or re-signed binary carries).
    """
    sig = OrderedDict([("present", True), ("ad_hoc", None), ("identifier", None)])
    if cs_abs + 12 > len(data):
        return sig
    magic, _length, count = struct.unpack_from(">III", data, cs_abs)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        return sig  # attached, but not the SuperBlob shape we know how to read
    for i in range(min(count, 64)):
        ie = cs_abs + 12 + i * 8
        if ie + 8 > len(data):
            break
        _slot, blob_off = struct.unpack_from(">II", data, ie)
        cd = cs_abs + blob_off
        if cd + 24 > len(data) or struct.unpack_from(">I", data, cd)[0] != CSMAGIC_CODEDIRECTORY:
            continue
        flags = struct.unpack_from(">I", data, cd + 12)[0]
        ident_off = struct.unpack_from(">I", data, cd + 20)[0]
        sig["ad_hoc"] = bool(flags & CS_ADHOC)
        sig["identifier"] = lc_string(data[cd:], ident_off)
        break
    return sig


def scan_strings(blob):
    """Suspicious indicators + embedded URLs/IPs from one slice's bytes."""
    hits = OrderedDict()
    for needle, note in SUSPICIOUS_STRINGS:
        if needle in blob:
            hits[needle.decode("ascii", "ignore").strip()] = note
    urls, ips = set(), set()
    for m in PRINTABLE_RE.finditer(blob):
        s = m.group().decode("ascii", "ignore")
        urls.update(URL_RE.findall(s))
        for ip in IP_RE.findall(s):
            if all(0 <= int(o) <= 255 for o in ip.split(".")):
                ips.add(ip)
    return hits, sorted(urls), sorted(ips)


def parse_slice(data, base):
    """Parse one Mach-O image starting at `base`. Never raises on bad input."""
    magic = data[base:base + 4]
    if magic not in MACH_MAGICS:
        return OrderedDict([("error", "not a Mach-O image at offset %d" % base)])
    endian, bits = MACH_MAGICS[magic]
    hdr_size = 32 if bits == 64 else 28
    if base + hdr_size > len(data):
        return OrderedDict([("error", "truncated Mach-O header")])

    _magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = \
        struct.unpack_from(endian + "IiiIIII", data, base)

    sl = OrderedDict([
        ("arch", arch_name(cputype, cpusubtype)),
        ("bits", bits),
        ("endian", "little" if endian == "<" else "big"),
        ("filetype", FILETYPES.get(filetype, "0x%x" % filetype)),
        ("ncmds", ncmds),
        ("flags", [name for bit, name in HEADER_FLAGS if flags & bit]),
        ("uuid", None),
        ("min_os", None),
        ("entry", None),
        ("dylinker", None),
        ("dylibs", []),
        ("rpaths", []),
        ("code_signature", OrderedDict([("present", False)])),
        ("encrypted", False),
    ])

    off, lc_start = base + hdr_size, base + hdr_size
    end = min(lc_start + sizeofcmds, len(data))
    for _ in range(ncmds):
        if off + 8 > end:
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", data, off)
        if cmdsize < 8:
            break
        buf = data[off:off + cmdsize]  # may be short if the file is truncated

        if cmd in DYLIB_CMDS:
            name = lc_string(buf, struct.unpack_from(endian + "I", buf, 8)[0]) if len(buf) >= 12 else None
            entry = OrderedDict([("kind", DYLIB_CMDS[cmd]), ("name", name)])
            (sl["dylibs"].append(entry) if cmd != LC_ID_DYLIB else sl.__setitem__("id_dylib", name))
        elif cmd == LC_RPATH and len(buf) >= 12:
            path = lc_string(buf, struct.unpack_from(endian + "I", buf, 8)[0])
            if path:
                sl["rpaths"].append(path)
        elif cmd == LC_LOAD_DYLINKER and len(buf) >= 12:
            sl["dylinker"] = lc_string(buf, struct.unpack_from(endian + "I", buf, 8)[0])
        elif cmd == LC_CODE_SIGNATURE and len(buf) >= 16:
            dataoff, datasize = struct.unpack_from(endian + "II", buf, 8)
            sl["code_signature"] = parse_code_signature(data, base + dataoff)
            sl["code_signature"]["data_size"] = datasize
        elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64) and len(buf) >= 20:
            # cryptid != 0 means a segment is encrypted (FairPlay / packed).
            if struct.unpack_from(endian + "I", buf, 16)[0] != 0:
                sl["encrypted"] = True
        elif cmd == LC_MAIN and len(buf) >= 16:
            entryoff = struct.unpack_from(endian + "Q", buf, 8)[0]
            sl["entry"] = OrderedDict([("kind", "LC_MAIN"), ("offset", "0x%x" % entryoff)])
        elif cmd == LC_UNIXTHREAD and sl["entry"] is None:
            sl["entry"] = OrderedDict([("kind", "LC_UNIXTHREAD"), ("offset", None)])
        elif cmd == LC_UUID and len(buf) >= 24:
            sl["uuid"] = buf[8:24].hex()
        elif cmd in VERSION_MIN_PLATFORM and len(buf) >= 16:
            ver, sdk = struct.unpack_from(endian + "II", buf, 8)
            sl["min_os"] = OrderedDict([
                ("platform", VERSION_MIN_PLATFORM[cmd]),
                ("min", decode_version(ver)), ("sdk", decode_version(sdk))])
        elif cmd == LC_BUILD_VERSION and len(buf) >= 20:
            platform, minos, sdk = struct.unpack_from(endian + "III", buf, 8)
            sl["min_os"] = OrderedDict([
                ("platform", BUILD_PLATFORMS.get(platform, "platform %d" % platform)),
                ("min", decode_version(minos)), ("sdk", decode_version(sdk))])

        off += cmdsize

    # String / IOC scan over this slice's own bytes.
    slice_end = len(data)
    sl["suspicious_strings"], sl["urls"], sl["ips"] = scan_strings(data[base:slice_end])
    sl["flags_triage"] = slice_flags(sl, filetype, flags)
    return sl


def slice_flags(sl, filetype, mh_flags):
    """Turn the parsed facts into a short list of things worth noting."""
    flags = []
    cs = sl["code_signature"]
    if not cs.get("present"):
        flags.append(("unsigned",
                       "no LC_CODE_SIGNATURE - binary is unsigned; Gatekeeper "
                       "blocks it and it may have been tampered with"))
    elif cs.get("ad_hoc"):
        flags.append(("ad_hoc_signed",
                      "ad-hoc signature (no signing identity) - not a Developer "
                      "ID and not notarizable as-is; normal for a locally built "
                      "binary, unusual for something handed to you as trusted"))
    if sl["encrypted"]:
        flags.append(("encrypted",
                      "LC_ENCRYPTION_INFO cryptid set - a segment is encrypted "
                      "(FairPlay / packer); static view of that segment is blind"))
    if filetype == 0x2 and not (mh_flags & MH_PIE):
        flags.append(("no_pie",
                      "MH_PIE unset - the main image loads at a fixed address "
                      "(no ASLR)"))
    if mh_flags & MH_ALLOW_STACK_EXECUTION:
        flags.append(("stack_exec", "MH_ALLOW_STACK_EXECUTION set - executable stack"))
    rel = [p for p in sl["rpaths"] if "@executable_path" in p or "@loader_path" in p]
    if rel:
        flags.append(("relative_rpath",
                      "rpath uses @executable_path/@loader_path (%s) - normal for "
                      "bundles, but a dylib-hijack surface worth checking" % ", ".join(rel)))
    if sl["suspicious_strings"]:
        flags.append(("suspicious_strings",
                      "%d flagged string(s): %s" % (len(sl["suspicious_strings"]),
                                                    ", ".join(sl["suspicious_strings"]))))
    return [OrderedDict([("id", fid), ("note", note)]) for fid, note in flags]


def triage(path):
    data = open(path, "rb").read()
    md5, sha256, size = file_hashes(path)
    head = data[:4]

    report = OrderedDict([
        ("file", path), ("size", size), ("md5", md5), ("sha256", sha256),
        ("format", None), ("slices", []),
    ])

    if head in FAT_MAGICS:
        fat_bits = FAT_MAGICS[head]
        nfat = struct.unpack_from(">I", data, 4)[0]
        if nfat > 64:  # almost certainly a Java .class (same 0xcafebabe magic)
            report["format"] = "not Mach-O (0xcafebabe but %d archs - likely a Java class)" % nfat
            return report
        report["format"] = "FAT/universal, %d architecture(s)" % nfat
        arch_size = 32 if fat_bits == 64 else 20
        for i in range(nfat):
            rec = 8 + i * arch_size
            if rec + arch_size > len(data):
                break
            if fat_bits == 64:
                offset = struct.unpack_from(">Q", data, rec + 8)[0]
            else:
                offset = struct.unpack_from(">I", data, rec + 8)[0]
            report["slices"].append(parse_slice(data, offset))
    elif head in MACH_MAGICS:
        report["format"] = "Mach-O (thin)"
        report["slices"].append(parse_slice(data, 0))
    else:
        report["format"] = "not a Mach-O binary (bad magic %s)" % head.hex()

    return report


def risk_label(report):
    score = 0
    for sl in report["slices"]:
        if "error" in sl:
            continue
        score += 2 * len(sl.get("flags_triage", []))
        score += len(sl.get("ips", []))
    if score >= 10:
        return "HIGH", score
    if score >= 4:
        return "MEDIUM", score
    return "LOW", score


def print_report(r):
    line = "=" * 64
    print(line)
    print("macho-triage: %s" % r["file"])
    print(line)
    print("MD5    : %s" % r["md5"])
    print("SHA256 : %s" % r["sha256"])
    print("Size   : %d bytes" % r["size"])
    print("Format : %s" % r["format"])
    label, score = risk_label(r)
    print("Risk   : %s (score %d)" % (label, score))

    for i, sl in enumerate(r["slices"]):
        print("\n" + "-" * 64)
        if "error" in sl:
            print("[ slice %d ]  %s" % (i, sl["error"]))
            continue
        print("[ slice %d ]  %s  %s  %d-bit %s-endian  (%d load commands)"
              % (i, sl["arch"], sl["filetype"], sl["bits"], sl["endian"], sl["ncmds"]))
        if sl["min_os"]:
            m = sl["min_os"]
            print("  min OS   : %s %s (SDK %s)" % (m["platform"], m["min"], m["sdk"]))
        if sl["entry"]:
            e = sl["entry"]
            print("  entry    : %s%s" % (e["kind"], " @ " + e["offset"] if e["offset"] else ""))
        if sl["flags"]:
            print("  hdr flags: %s" % ", ".join(sl["flags"]))
        if sl["uuid"]:
            print("  uuid     : %s" % sl["uuid"])

        cs = sl["code_signature"]
        if not cs.get("present"):
            print("  signature: UNSIGNED")
        else:
            kind = "ad-hoc" if cs.get("ad_hoc") else "identity"
            ident = cs.get("identifier") or "?"
            print("  signature: present (%s)  id=%s" % (kind, ident))

        print("  dylibs   : %d" % len(sl["dylibs"]))
        for d in sl["dylibs"]:
            tag = "" if d["kind"] == "LC_LOAD_DYLIB" else "  [%s]" % d["kind"]
            print("    - %s%s" % (d["name"], tag))
        if sl["rpaths"]:
            print("  rpaths   : %s" % ", ".join(sl["rpaths"]))

        print("  [ suspicious strings ]  %d" % len(sl["suspicious_strings"]))
        for name, note in sl["suspicious_strings"].items():
            print("    ! %-26s %s" % (name, note))
        if sl["urls"]:
            print("  [ embedded URLs ]  %d" % len(sl["urls"]))
            for u in sl["urls"][:30]:
                print("    - %s" % u)
        if sl["ips"]:
            print("  [ embedded IPs ]  %d" % len(sl["ips"]))
            for ip in sl["ips"][:30]:
                print("    - %s" % ip)

        print("  [ flags ]  %d" % len(sl["flags_triage"]))
        for f in sl["flags_triage"]:
            print("    ! %-18s %s" % (f["id"], f["note"]))
    print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Static triage for a macOS Mach-O binary.")
    ap.add_argument("binary", help="path to the Mach-O file")
    ap.add_argument("--json", action="store_true", help="emit a JSON report instead of text")
    args = ap.parse_args(argv)

    try:
        report = triage(args.binary)
    except FileNotFoundError:
        sys.exit("error: no such file: %s" % args.binary)
    except IsADirectoryError:
        sys.exit("error: %s is a directory" % args.binary)

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print_report(report)


if __name__ == "__main__":
    main()
