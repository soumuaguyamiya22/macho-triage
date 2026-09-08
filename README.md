# macho-triage

A small, dependency-free static triage tool for macOS Mach-O binaries. Point it
at a binary you don't fully trust and it prints the things you look at first:
the header (arch, file type, hardening flags), the dylibs it links, whether it
carries a code signature and whether that signature is ad-hoc, its rpaths, entry
point and minimum OS, plus any suspicious strings / embedded URLs / IPs.

Everything is static. The file is read once and parsed with `struct` - nothing
is executed - so it's safe to point at a sample you don't trust. Fat / universal
binaries are walked slice by slice.

## Why

`otool -L`, `codesign -dv` and `strings | grep` each answer a piece of this, but
that's three tools and a pile of flags, and `codesign` isn't always on the box
you're working from. Before I decide whether a dropped Mach-O is worth opening in
a disassembler I want the same short list every time: who it links, whether it's
signed and how, where it says it'll load things from, and anything that looks
like it talks to the network or runs a shell. So this prints that list and gets
out of the way. It's a first pass, not a verdict.

## Usage

```bash
python3 macho_triage.py /path/to/binary
```

JSON, for feeding the result into something else:

```bash
python3 macho_triage.py /path/to/binary --json > report.json
```

Requires Python 3.8+. No third-party packages.

## Example

A clean, Apple-signed system binary (`/bin/ls`, copied out to a scratch path).
It's universal, so both slices are reported; the arm64e slice is trimmed here:

```
================================================================
macho-triage: ls.sample
================================================================
MD5    : 90614fbf4534ad5a203057ab7f921389
SHA256 : 3be943172b502b245545fbfd57706c210fabb9ee058829c5bf00c3f67c8fb474
Size   : 154624 bytes
Format : FAT/universal, 2 architecture(s)
Risk   : LOW (score 0)

----------------------------------------------------------------
[ slice 0 ]  x86_64  MH_EXECUTE  64-bit little-endian  (18 load commands)
  min OS   : macOS 10.14.0 (SDK 15.7.0)
  entry    : LC_MAIN @ 0x978
  hdr flags: NOUNDEFS, TWOLEVEL, PIE
  uuid     : 9870fe5380583665b28a2bfe57a7e3d2
  signature: present (identity)  id=com.apple.ls
  dylibs   : 3
    - /usr/lib/libutil.dylib
    - /usr/lib/libncurses.5.4.dylib
    - /usr/lib/libSystem.B.dylib
  [ suspicious strings ]  0
  [ embedded URLs ]  4
    - http://crl.apple.com/codesigning.crl0
    - http://www.apple.com/DTDs/PropertyList-1.0.dtd
    - http://www.apple.com/appleca/root.crl0
    - https://www.apple.com/appleca/0
  [ flags ]  0

----------------------------------------------------------------
[ slice 1 ]  arm64e  MH_EXECUTE  64-bit little-endian  (20 load commands)
  ... same three dylibs, identity-signed com.apple.ls (trimmed)
================================================================
```

Those apple.com CRL/OCSP URLs are pulled out of the embedded signature's
certificate chain - expected noise on anything Apple-signed, not an indicator.

And a locally built test stub carrying the strings a macOS stealer usually trips
(synthetic throughout - RFC 5737 addresses, `example.com`):

```
================================================================
macho-triage: stub
================================================================
MD5    : e2d88c11cc57ae18d3053ecf5ef01916
SHA256 : 80a0012e9d00b062e08053c4b50760f1124e4e6ee7811e3f8b80be25d80571cc
Size   : 49976 bytes
Format : Mach-O (thin)
Risk   : MEDIUM (score 6)

----------------------------------------------------------------
[ slice 0 ]  arm64  MH_EXECUTE  64-bit little-endian  (18 load commands)
  min OS   : macOS 15.0.0 (SDK 15.5.0)
  entry    : LC_MAIN @ 0x4f8
  hdr flags: NOUNDEFS, TWOLEVEL, PIE
  uuid     : 14c9491ec22239c89994013d2ef6c88d
  signature: present (ad-hoc)  id=stub
  dylibs   : 1
    - /usr/lib/libSystem.B.dylib
  [ suspicious strings ]  5
    ! NSTask                     spawns child processes (NSTask)
    ! osascript                  runs AppleScript (osascript) - UI scripting / persistence
    ! /bin/sh                    references the shell
    ! SecItemCopyMatching        Keychain item lookup (credential access)
    ! LaunchAgents               references LaunchAgents (launchd persistence)
  [ embedded URLs ]  1
    - http://203.0.113.10/gate.php
  [ embedded IPs ]  2
    - 198.51.100.23
    - 203.0.113.10
  [ flags ]  2
    ! ad_hoc_signed      ad-hoc signature (no signing identity) - not a Developer ID and not notarizable as-is; normal for a locally built binary, unusual for something handed to you as trusted
    ! suspicious_strings 5 flagged string(s): NSTask, osascript, /bin/sh, SecItemCopyMatching, LaunchAgents
================================================================
```

`codesign -dv` on that same stub agrees: `flags=0x20002(adhoc,linker-signed)`.

## How it works

- The **header** gives arch (incl. arm64e), file type and the MH_* flags; `PIE`
  and `ALLOW_STACK_EXECUTION` are the two worth a glance.
- **Load commands** are walked with `struct`: `LC_LOAD_DYLIB` and its weak /
  reexport / upward variants for the link list, `LC_RPATH` for search paths,
  `LC_LOAD_DYLINKER`, `LC_MAIN` / `LC_UNIXTHREAD` for the entry point,
  `LC_BUILD_VERSION` / `LC_VERSION_MIN_*` for the min OS, `LC_UUID`, and
  `LC_ENCRYPTION_INFO` for an encrypted segment.
- **Signing** comes from `LC_CODE_SIGNATURE`: the embedded SuperBlob is parsed
  far enough to read the CodeDirectory's flags (the `adhoc` bit) and the signing
  identifier. Nothing is *verified* - see the note below.
- **Strings / URLs / IPs** are a substring + printable-string pass over each
  slice's bytes. The suspicious-string list in `macho_triage.py` is a plain
  `(needle, note)` table that's easy to extend.

The risk label is a weighted count of flags and embedded IPs - a sort order, not
a judgement. Read the report.

## Notes / limitations

- **A signature here only means a signature is *attached*.** It does not
  recompute the CDHash, walk the certificate chain, or check notarization - for
  "will Gatekeeper actually trust this", use `codesign --verify` / `spctl -a`.
  What it tells you cheaply is signed-vs-unsigned and identity-vs-ad-hoc, which
  is usually the first fork in the road.
- Substring matching means a packed or obfuscated sample can keep its strings
  away from it. A clean result is not a clean sample.
- It reads headers and load commands, not disassembly; once triage says a sample
  is interesting, open it in a real tool.

The rules I write up from what this finds live in
[detections-notes](https://github.com/soumuaguyamiya22/detections-notes).

## License

MIT
