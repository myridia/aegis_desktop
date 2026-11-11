<img src="aegis_desktop.svg" alt="Aegis Desktop logo" width="120">

# Aegis Desktop

A small, read-only macOS viewer for [Aegis Authenticator](https://github.com/beemdevelopment/Aegis)
exports. It shows TOTP, HOTP and Steam codes, copies them to the clipboard and
never writes to the vault.

Built with [NAppGUI](https://nappgui.com) (C, MIT) and OpenSSL 3 for the crypto.

## Features

- Opens plain (`"db": { ... }`) and password-encrypted (`"db": "base64..."`)
  Aegis JSON exports.
- Supports TOTP (SHA1/SHA256/SHA512, 4-10 digits, custom period), HOTP and
  Steam Guard codes.
- Live search filter by issuer/account.
- Click a row to copy its current code. `Cmd+N` advances and copies the next
  HOTP counter value.
- `Cmd+O` open, `Cmd+F` filter box, `Cmd+C` copy the selected row.
- Codes refresh automatically once per second; the `Left` column counts down
  the current time step.

## Build

Requirements:

- macOS with Xcode command line tools (tested on Intel / Ventura).
- NAppGUI SDK installed at `/usr/local/nappgui` (x86_64).
- OpenSSL 3 from Homebrew (`brew install openssl@3`).

```bash
cd /Users/veto/webs/old/aegis_desktop
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
open build/AegisDesktop.app
```

If the SDK lives elsewhere, pass it explicitly:

```bash
cmake -S . -B build \
  -Dnappgui_DIR=/path/to/nappgui/cmake \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DDEPLOYMENT_TARGET_OSX=13.6
```

The result is `build/AegisDesktop.app` (or `build/Release/AegisDesktop.app`
with the Xcode generator).

## Getting a vault out of Aegis

On the phone: **Settings → Import & Export → Export** (plain or encrypted).
Copy the resulting `.json` file to the Mac (AirDrop, USB, etc.) and open it
with `Cmd+O`.

## Security model

- Read-only: the vault file is opened with `fopen(..., "rb")` and never
  written, renamed or modified.
- No network code is linked or called.
- Decrypted JSON, derived keys, master key and raw secrets are wiped from
  memory (`secure_wipe`) as soon as they are no longer needed. Secrets live
  only in RAM while a vault is open.
- The vault password is kept in memory only for the duration of the unlock
  attempt and is wiped afterwards.
- Aegis "biometric" key slots cannot be decrypted off-device; only the
  password slot is used. A vault that only has a biometric slot is rejected
  with an explanatory message.
- scrypt parameters are sanity-checked (`n` power of two in [1024, 131072],
  `r`/`p` in [1, 16], bounded work and memory) before deriving keys, so a
  crafted export cannot force huge CPU/memory use.
- AES-256-GCM tags are verified before any plaintext is parsed; a wrong
  password or a corrupted file is detected instead of yielding garbage.

## Project layout

```
src/main.c        NAppGUI entry point (osmain_sync 0.25 s ticker)
src/gui.c/.h      window, toolbar, table, filter, unlock flow, hotkeys
src/clipboard.m   macOS NSPasteboard shim
src/vault.c/.h    Aegis JSON loading + scrypt/AES-256-GCM decryption
src/otp.c/.h      HMAC-SHA1/256/512, RFC 4226/6238, Steam alphabet
src/json.c/.h     minimal JSON DOM parser
src/util.c/.h     base64/base32/hex decoders, secure wipe
```

## Notes

- HOTP counter increments happen in memory only; the export on disk is never
  updated. Re-open the export to start again from the file's counters.
- If signing/paths change, adjust `DEPLOYMENT_TARGET_OSX` to match the
  NAppGUI SDK build (`/usr/local/nappgui/cmake/NAppGUIOptions.txt`).
