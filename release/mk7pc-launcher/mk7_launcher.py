"""
mk7_launcher.py - the GUI you ship as an .exe.

Flow:  1) pick your own decrypted MK7 dump   2) Verify & extract   3) Update runtime   4) Play
CLI:   python mk7_launcher.py --cli <rom> [--manifest URL]
"""
import os
import queue
import sys
import threading

import mk7_core as core

DEFAULT_MANIFEST = "https://example.com/mk7pc/manifest.json"   # <- change to where YOU host your files


def run_cli(argv):
    rom = argv[0]
    url = argv[argv.index("--manifest") + 1] if "--manifest" in argv else None
    manifest = core.fetch_json(url) if url else {}
    data_dir, meta = core.prepare_rom(rom, manifest.get("known_roms"))
    print("Ready:", data_dir, meta)
    if manifest:
        core.sync_runtime(manifest)


def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    cfg = core.load_config()
    q = queue.Queue()
    state = {"data_dir": None, "busy": False, "manifest": None}

    root = tk.Tk()
    root.title("Mario Kart 7 PC - Launcher")
    root.geometry("640x460")
    root.minsize(560, 420)

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    frm.columnconfigure(1, weight=1)

    rom_var = tk.StringVar(value=cfg.get("rom", ""))
    url_var = tk.StringVar(value=cfg.get("manifest_url", DEFAULT_MANIFEST))

    ttk.Label(frm, text="Your game dump (decrypted):").grid(row=0, column=0, sticky="w", pady=4)
    ttk.Entry(frm, textvariable=rom_var).grid(row=0, column=1, sticky="ew", padx=6)
    ttk.Button(frm, text="Browse...", command=lambda: browse()).grid(row=0, column=2)

    ttk.Label(frm, text="Update server (manifest URL):").grid(row=1, column=0, sticky="w", pady=4)
    ttk.Entry(frm, textvariable=url_var).grid(row=1, column=1, columnspan=2, sticky="ew", padx=6)

    btns = ttk.Frame(frm)
    btns.grid(row=2, column=0, columnspan=3, sticky="ew", pady=8)
    b_extract = ttk.Button(btns, text="1. Verify && extract ROM", command=lambda: start(do_extract))
    b_update = ttk.Button(btns, text="2. Update runtime", command=lambda: start(do_update))
    b_play = ttk.Button(btns, text="3. Play", command=lambda: play(), state="disabled")
    for b in (b_extract, b_update, b_play):
        b.pack(side="left", padx=4)

    bar = ttk.Progressbar(frm, maximum=100)
    bar.grid(row=3, column=0, columnspan=3, sticky="ew", pady=4)
    logbox = tk.Text(frm, height=14, state="disabled", wrap="word")
    logbox.grid(row=4, column=0, columnspan=3, sticky="nsew")
    frm.rowconfigure(4, weight=1)

    ttk.Label(frm, text="You must supply your own legally obtained game dump. "
                        "This launcher does not download any Nintendo code or assets.",
              wraplength=600, foreground="#666").grid(row=5, column=0, columnspan=3, sticky="w", pady=(8, 0))

    # ---- thread-safe UI plumbing: workers only put messages on the queue
    def log(msg):
        q.put(("log", str(msg)))

    def progress(done, total):
        q.put(("bar", 100.0 * done / max(total, 1)))

    def pump():
        try:
            while True:
                kind, val = q.get_nowait()
                if kind == "log":
                    logbox.config(state="normal")
                    logbox.insert("end", val + "\n")
                    logbox.see("end")
                    logbox.config(state="disabled")
                elif kind == "bar":
                    bar["value"] = val
                elif kind == "done":
                    state["busy"] = False
                    for b in (b_extract, b_update):
                        b.config(state="normal")
                    b_play.config(state="normal" if state["data_dir"] else "disabled")
                elif kind == "error":
                    messagebox.showerror("Problem", val)
        except queue.Empty:
            pass
        root.after(100, pump)

    def browse():
        p = filedialog.askopenfilename(title="Select your decrypted dump",
                                       filetypes=[("3DS dumps", "*.3ds *.cci *.cxi *.app *.cia"), ("All files", "*.*")])
        if p:
            rom_var.set(p)

    def start(fn):
        if state["busy"]:
            return
        state["busy"] = True
        for b in (b_extract, b_update, b_play):
            b.config(state="disabled")
        cfg["rom"], cfg["manifest_url"] = rom_var.get(), url_var.get()
        core.save_config(cfg)

        def worker():
            try:
                fn()
            except core.RomError as e:
                log("ERROR: %s" % e)
                q.put(("error", str(e)))
            except Exception as e:  # network errors, disk errors, ...
                log("ERROR: %s" % e)
                q.put(("error", "Unexpected error: %s" % e))
            finally:
                q.put(("bar", 0))
                q.put(("done", None))
        threading.Thread(target=worker, daemon=True).start()

    def get_manifest():
        if state["manifest"] is None:
            log("Fetching manifest ...")
            state["manifest"] = core.fetch_json(url_var.get().strip())
        return state["manifest"]

    def do_extract():
        rom = rom_var.get().strip()
        if not os.path.isfile(rom):
            raise core.RomError("Pick your game dump first.")
        known = None
        try:
            known = get_manifest().get("known_roms")
        except Exception as e:
            log("Couldn't reach the update server (%s). Continuing without hash check." % e)
        state["data_dir"], meta = core.prepare_rom(rom, known, progress, log)
        log("ROM ready: %s (%s)" % (meta["label"], meta["region"]))

    def do_update():
        m = get_manifest()
        core.sync_runtime(m, progress, log)
        log("Runtime is up to date (version %s)." % m.get("version", "?"))

    def play():
        try:
            m = state["manifest"] or {}
            core.launch(m.get("entry", "mk7pc.exe"), state["data_dir"])
        except core.RomError as e:
            messagebox.showerror("Can't start", str(e))

    # If a previous extraction is cached for this ROM path we can't know without hashing; user clicks step 1.
    root.after(100, pump)
    root.mainloop()


if __name__ == "__main__":
    if "--cli" in sys.argv:
        run_cli(sys.argv[sys.argv.index("--cli") + 1:])
    else:
        run_gui()
