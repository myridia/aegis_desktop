# AGENTS.md — aegis_desktop

## What this is
Read-only macOS viewer for [Aegis Authenticator](https://github.com/beemdevelopment/Aegis)
exports. Shows TOTP, HOTP and Steam codes, copies them to the clipboard, never
writes to the vault.

## Stack
- C (C99) with Objective-C (`src/clipboard.m`) — built with CMake (>= 3.16)
- [NAppGUI](https://nappgui.com) SDK precompiled at `/usr/local/nappgui` (x86_64, macOS 13.6)
- OpenSSL 3 from Homebrew (`openssl@3`) for scrypt / AES-256-GCM
- No network code; Cocoa / UniformTypeIdentifiers / WebKit frameworks

## Build / run
The user builds and runs (`./run.sh`, which is cmake + build + `open` the .app).
The agent never compiles, builds, or runs anything. Target is macOS
(x86_64, deployment target 13.6) — it does not build on the Linux dev container.

## Layout
- `src/main.c` — entry point (`osmain_sync` 0.25 s ticker)
- `src/gui.c/.h` — window, toolbar, table, filter, unlock flow, hotkeys
- `src/clipboard.m/.h` — NSPasteboard shim
- `src/vault.c/.h` — Aegis JSON loading + scrypt/AES-256-GCM decryption
- `src/otp.c/.h` — HMAC-SHA1/256/512, RFC 4226/6238, Steam alphabet
- `src/json.c/.h` — minimal JSON DOM parser
- `src/util.c/.h` — base64/base32/hex decoders, `secure_wipe`
- `ask.sh` — task switch; tasks live in `ask.d/`
- `ask.d/install_nappgui_macos.sh` — task 1: clone `nappgui_src` (if missing), build, install to `/usr/local/nappgui`
- `ask.d/install_openssl_macos.sh` — task 2: `brew install openssl@3`
- `ask.d/run.sh` — task 3: runs `./run.sh` (configure, build, open the app)

## Conventions / security model
- The vault file is opened read-only (`fopen(..., "rb")`); never written, renamed, or modified.
- No network access, ever — do not add networking.
- Secrets (decrypted JSON, derived keys, master key, raw secrets) are wiped with
  `secure_wipe` as soon as they are no longer needed. Keep it that way in every edit.
- Aegis "biometric" key slots cannot be decrypted off-device; only the password slot is used.
- scrypt parameters are sanity-checked before deriving keys; AES-256-GCM tags are
  verified before any plaintext is parsed. Keep those checks intact on edits to `vault.c`.
- HOTP counter increments happen in memory only.
- No comments in code unless asked.
