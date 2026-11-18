<img src="aegis_desktop.svg" alt="Aegis Desktop logo" width="120">

# Aegis Desktop

A small, desktop viewer for [Aegis Authenticator](https://github.com/beemdevelopment/Aegis)
exports — macOS, Linux and Windows. It shows TOTP, HOTP and Steam codes, copies them to the
clipboard; deleting a row rewrites the currently loaded export (see Security model).

Built with [NAppGUI](https://nappgui.com) (C, MIT) and OpenSSL 3 for the crypto.

## Features

- Imports plain (`"db": { ... }`) and password-encrypted (`"db": "base64..."`)
  Aegis JSON exports. The export is copied into the app's own storage
  (`~/.config/aegis_desktop/imported.json` on POSIX,
  `%APPDATA%\Aegis Desktop\imported.json` on Windows, mode 0600) — the file you
  picked is opened read-only and never written; all later reads, deletes and
  rewrites happen against the app's own copy. Re-importing the original pulls
  everything back again.
- Supports TOTP (SHA1/SHA256/SHA512, 4-10 digits, custom period), HOTP and
  Steam Guard codes.
- Live search filter by issuer/account.
- Remembers the app's imported copy (`~/.config/aegis_desktop/imported.json`,
  `%APPDATA%\Aegis Desktop\imported.json` on Windows) and re-imports it automatically
  on the next start (see the first bullet).
- Exports the vault as an Aegis backup (`File` menu → `Export to Aegis...`):
  empty password writes an unencrypted Aegis JSON export; any password writes an
  encrypted one (scrypt + AES-256-GCM) that re-imports into the app and into Aegis.
- Click a row to copy its current code. `Cmd/Win+N` (⌘N on macOS, Win/Super+N on
  Windows/Linux) advances and copies the next HOTP counter value.
- Delete toolbar button permanently removes the selected entry: the row is
  removed from memory and the app's own imported copy is rewritten without it
  (a backup `<imported.json>.bak-<timestamp>` is kept beside it first). Your
  original Aegis export is never written. Encrypted exports ask for the vault
  password again before saving the deletion.
- `Cmd/Win+O` import, `Cmd/Win+F` filter box, `Cmd/Win+C` copy the selected row,
  `Cmd/Win+E` export to Aegis (menu `File` → `Export to Aegis...`), `Del` delete the
  selected entry (on macOS use fn+Delete — plain Backspace stays available for typing
  in the filter box).
- Codes refresh automatically once per second; the `Left` column counts down
  the current time step.

## Build

Requirements:

- macOS with Xcode command line tools, Linux (GTK3 dev), or Windows with Visual Studio + CMake.
- NAppGUI SDK installed at `/usr/local/nappgui` (see `./ask.sh` — task 1 Windows / 2 macOS / 3 Linux).
- OpenSSL 3 (macOS: `brew install openssl@3`; Linux: `sudo apt install libssl-dev`; Windows: via vcpkg with the static triplet `x64-windows-static` (static libs + static CRT, matches NAppGUI — ships a self-contained exe))

```bash
./build.sh
```

The result is `build/Release/bin/aegis_desktop.app` (macOS),
`build/Release/bin/aegis_desktop` (Linux) or `build/Release/bin/aegis_desktop.exe`
(Windows). `./build.sh` deletes `build/` first, then configures, builds and launches
the app.

If the SDK lives elsewhere, pass it explicitly:

```bash
cmake -S . -B build \
  -Dnappgui_DIR=/path/to/nappgui/cmake
```

### CI

Pushes to `main` and tags run `.github/workflows/control.yml`, which dispatches the per-platform workflows
(Linux, macOS arm64 + Intel, Windows, Debian package, signed MSIX — via manual dispatch you can pick a single target).
Release assets upload on every run.

## Getting a vault out of Aegis

On the phone: **Settings → Import & Export → Export** (plain or encrypted).
Copy the resulting `.json` file to your computer (AirDrop, USB, scp, …) and import it
with `Cmd/Win+O`.

## Security model

- The export you pick is opened read-only and copied into the app's own storage (`imported.json` in the app config dir); only that copy is ever mutated — by `Del`/the Delete button (rewritten with a `.bak-<timestamp>` backup beside it). Your original export is never written. Encrypted exports re-enter the password (verified against the file) before a deletion is saved.
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
build.sh             configure + build + launch (deletes build/ first)
ask.sh               task switch: 1 Windows / 2 macOS / 3 Linux NAppGUI install, 4 build & run
src/main.c           NAppGUI entry point (osmain_sync 0.25 s ticker)
src/gui.c/.h         window, toolbar, table, filter, unlock flow, hotkeys, last-import reload
src/osx/clipboard.m  macOS NSPasteboard shim
src/gtk/clipboard.c  Linux (GTK3) clipboard shim
src/win/clipboard.c  Windows clipboard shim
src/res/             NAppGUI template icons (replace with your own artwork if you like)
src/Info.plist       static macOS bundle plist
src/vault.c/.h       Aegis JSON loading + scrypt/AES-256-GCM decryption
src/otp.c/.h         HMAC-SHA1/256/512, RFC 4226/6238, Steam alphabet
src/json.c/.h        minimal JSON DOM parser
src/util.c/.h        base64/base32/hex decoders, secure wipe
```

## Notes

- HOTP counter increments happen in memory only; the export on disk is never
  updated. Re-import the export to start again from the file's counters.
