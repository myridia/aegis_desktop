# AGENTS.md — aegis_desktop

## What this is
Read-only desktop viewer for [Aegis Authenticator](https://github.com/beemdevelopment/Aegis)
exports. Shows TOTP, HOTP and Steam codes, copies them to the clipboard, never
writes to the vault. Cross-platform: macOS, Linux, Windows — NAppGUI project layout
(`nap_project_desktop_app` / `nap_desktop_app`, like `code/tamuz_desktop`).

## Stack
- C (C99); Objective-C only on macOS (`src/osx/clipboard.m`)
- [NAppGUI](https://nappgui.com) SDK at `/usr/local/nappgui` (Xcode build on macOS, Release on Linux/Windows)
- OpenSSL 3 for scrypt / AES-256-GCM (macOS: Homebrew `openssl@3`; Linux: `libssl-dev`; Windows: OpenSSL 3 for Windows)
- No network code

## Build / run
The user builds and runs (`./build.sh`, wired into `./ask.sh` task 4 — deletes
`build/`, configures, builds, launches: `open` the `.app` on macOS, exec the
binary elsewhere). The agent never compiles, builds, or runs anything.

## Layout
- `src/main.c` — entry point (`osmain_sync` 0.25 s ticker)
- `src/gui.c/.h` — window, toolbar, table, filter, unlock flow, hotkeys
- `src/osx/clipboard.m` — macOS NSPasteboard shim (Darwin-only subdir)
- `src/gtk/clipboard.c` — Linux clipboard shim (GTK3; NAppGUI/Linux is GTK-based, `src/gtk/` wires the GTK include dirs)
- `src/win/clipboard.c` — Windows clipboard shim (Win32 CF_UNICODETEXT)
- `src/clipboard.h` — clipboard shim interface
- `src/vault.c/.h` — Aegis JSON loading + scrypt/AES-256-GCM decryption
- `src/otp.c/.h` — HMAC-SHA1/256/512, RFC 4226/6238, Steam alphabet
- `src/json.c/.h` — minimal JSON DOM parser
- `src/util.c/.h` — base64/base32/hex decoders, `secure_wipe`
- `src/res/` — NAppGUI template icons (`logo.icns`, `logo48.ico`, `logo256.ico`)
- `src/Info.plist` — static macOS bundle plist (nap uses it if present)
- `ask.sh` — task switch; tasks live in `ask.d/` (1 Windows / 2 macOS / 3 Linux NAppGUI install, 4 build & run)
- `ask.d/install_nappgui_macos.sh` — task 2: install NAppGUI (Xcode) + `brew install openssl@3`
- `ask.d/install_nappgui_linux.sh` — task 3: apt-installs `libgtk-3-dev`/`pkg-config`/`libssl-dev` if missing, then NAppGUI Release, `sudo` install
- `run.sh` — unused leftover, superseded by `build.sh` (kept; delete at user's discretion)

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
