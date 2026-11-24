# BleachSan handover

- The 1.2 branch changes the default cleanup catalogue, read-only discovery, storage views, and Windows executable launch.
- [README](README.md) documents build, launch, scan commands and existing scheduled tasks.
- [Release decisions](docs/release-1.2.md) records the research and rule boundaries.
- The lockfile pins the Windows x64 build. Run cargo test for the workspace with the locked dependency graph.
- Distribute the versioned executable through the [1.2 release](https://github.com/Metanoyd/Bleach-San/releases/tag/v1.2.0), with its SHA-256 in the release notes.
- Preserve previous releases and the existing local copies until the owner verifies 1.2 and approves their removal.
