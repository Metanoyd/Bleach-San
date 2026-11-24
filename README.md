# BleachSan 1.2

BleachSan is a Windows x64 storage cleaner and analyzer built in Rust with Slint.

## Run it

Download the versioned executable from [GitHub Releases](https://github.com/Metanoyd/Bleach-San/releases). Double-click it for the GUI. Routine scans and cache cleanup use the caller’s Windows permissions. Creating a Windows restore point is an explicit administrator action.

- **Cleaner** scans known application cache locations and your local Temp files last changed at least seven days ago.
- **Include read-only discoveries** checks more locations for likely caches, development output, and other items to inspect.
- **Storage** ranks readable folders on the selected drive. **Large Files** lists files by size and can locate them in Explorer.
- Review the selected locations, then confirm cleanup of their current eligible files. A browser or application that is open can block its cache cleanup. The result reports skipped files and errors.

Storage totals are logical file lengths. NTFS compression, sparse files, hard links, and concurrent activity can change the observed free-space gain. Linked and inaccessible directory entries are skipped. See [release research notes](docs/release-1.2.md) for the rule boundaries.

When upgrading from 1.1 with scheduled cleanup enabled, the existing Windows task continues to use the executable it was registered with. Check its action in Task Scheduler before relying on 1.2 rules and re-register it from the version you intend to run.

## Build and test

Use a Windows x64 Rust toolchain and the Visual Studio Developer Command Prompt.

```powershell
cargo test --workspace --locked
cargo build -p cleaner-app --release --locked
```

The executable is at `target\release\bleachsan.exe`. For terminal output from PowerShell, run it with `Start-Process -NoNewWindow -Wait`.

```powershell
Start-Process -NoNewWindow -Wait .\target\release\bleachsan.exe -ArgumentList '--scan','--drive','C:'
Start-Process -NoNewWindow -Wait .\target\release\bleachsan.exe -ArgumentList '--scan','--discover','--drive','C:'
Start-Process -NoNewWindow -Wait .\target\release\bleachsan.exe -ArgumentList '--analyze','--drive','C:'
```

`--clean-safe` and `--scheduled` are destructive commands for verified default categories. Use `--scan` to preview the categories first.

## Source layout

- `crates/cleaner-app` is the Windows executable and CLI.
- `crates/cleaner-ui` contains the Slint interface and worker bridge.
- `crates/cleaner-core` owns rule selection, previews, cleanup, and storage analysis.
- `crates/cleaner-platform-windows` owns Windows-specific filesystem, process, and shell operations.
- `rules` contains the rule catalogue. The loader activates the recipes audited for 1.2.
