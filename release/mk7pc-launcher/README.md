# MK7 PC Launcher

Player flow: pick own decrypted dump -> Verify & extract -> Update runtime -> Play.

- `mk7_core.py`      ROM parsing, ExeFS/RomFS extraction, hash-verified downloads (no GUI deps)
- `mk7_launcher.py`  Tkinter GUI (CLI: `python mk7_launcher.py --cli <rom> [--manifest URL]`)
- `test_core.py`     Tests on a synthetic image (`python -m unittest test_core`)
- `build.bat`        Windows build -> `dist\MK7PC-Launcher.exe`
- `.github/workflows/build.yml`  Same build in GitHub Actions (no local Windows needed)
- `manifest.example.json`  What you host next to your runtime files
- `make_manifest.py` Generates manifest.json (with hashes) from a folder of your runtime files

Set `DEFAULT_MANIFEST` in `mk7_launcher.py` to your own HTTPS URL before building.
Host only YOUR files. Never upload code.bin, RomFS contents, keys, or dumps.

Cache lives in `%LOCALAPPDATA%\MK7PC` (`runtime\`, `data\<romhash>\{exefs,romfs}`).
The runtime is started as: `mk7pc.exe --data <data dir>`.

Not yet validated against a real dump: the parsers follow the documented NCSD/NCCH/ExeFS/RomFS
layouts and pass synthetic tests, but test with your own ROM and fix any surprises.
Supported: decrypted .3ds/.cci, .cxi, and decrypted .cia (first content = game).
Not supported yet: encrypted dumps/CIAs, update/DLC patch merging.
