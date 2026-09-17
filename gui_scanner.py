"""
gui_scanner.py — Modern CustomTkinter GUI Dashboard for ThreatScanner.

Opens as a windowed (non-console) application.
Shortcuts created by the installer will point here.
The CLI version (cli_scanner.py) remains separately accessible.
"""

import sys
import os
import threading
from datetime import datetime

# Ensure 'app' module can be imported when run from the dist directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import customtkinter as ctk
from tkinter import filedialog, messagebox

from updater import check_for_updates
from version import APP_VERSION

# ─── Theme ────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ICICI colours
ORANGE = "#F37224"
NAVY   = "#1C3E73"
RED    = "#E8300B"
GREEN  = "#22C55E"
BG     = "#0F172A"     # deep navy background
CARD   = "#1E293B"     # card surface
BORDER = "#334155"     # subtle divider
TEXT   = "#F1F5F9"
MUTED  = "#94A3B8"


# ─────────────────────────────────────────────────────────────────────────────
class ThreatScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title(f"URL Threat Scanner  v{APP_VERSION}")
        self.geometry("1000x720")
        self.minsize(860, 600)
        self.configure(fg_color=BG)

        # Set window icon if available
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "Installer", "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        self._build_ui()

        # Run update check in background so UI doesn't block
        threading.Thread(target=self._background_update_check, daemon=True).start()

    # ── Background update check ───────────────────────────────────────────────
    def _background_update_check(self):
        check_for_updates(
            current_version=APP_VERSION,
            silent=True,
            log_callback=lambda msg: self.after(0, self._append_log, msg),
        )

    # ── UI Construction ───────────────────────────────────────────────────────
    def _build_ui(self):
        # ── Top header bar ────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color=NAVY, corner_radius=0, height=62)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text="🔐  URL Threat Scanner",
            font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold"),
            text_color="white",
        ).pack(side="left", padx=24, pady=0)

        right_header = ctk.CTkFrame(header, fg_color="transparent")
        right_header.pack(side="right", padx=24)

        ctk.CTkLabel(
            right_header,
            text=f"v{APP_VERSION}  |  ICICI Bank — Information Security Group",
            font=ctk.CTkFont(size=11),
            text_color="#93C5FD",
        ).pack(side="left", padx=(0, 16))

        # About Button
        ctk.CTkButton(
            right_header,
            text="ℹ️ About",
            width=60,
            height=26,
            fg_color="transparent",
            border_color="#3B82F6",
            border_width=1,
            text_color="white",
            hover_color="#1E3A8A",
            font=ctk.CTkFont(size=11),
            corner_radius=6,
            command=self._show_about,
        ).pack(side="left")

        # ── Main layout: left panel + right log ───────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=12)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)
        body.rowconfigure(0, weight=1)

        self._build_left_panel(body)
        self._build_right_panel(body)

    def _build_left_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        panel.columnconfigure(0, weight=1)

        # ── Section: URL Input ────────────────────────────────────────────────
        self._section_label(panel, "🌐  URLs to Scan", row=0)

        self.url_box = ctk.CTkTextbox(
            panel,
            height=160,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color="#0F172A",
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            corner_radius=8,
        )
        self.url_box.grid(row=1, column=0, padx=16, pady=(4, 2), sticky="ew")
        self.url_box.insert("end", "https://example.com\nhttps://another-url.com")

        ctk.CTkLabel(
            panel,
            text="Enter one URL per line",
            font=ctk.CTkFont(size=11),
            text_color=MUTED,
        ).grid(row=2, column=0, padx=18, sticky="w", pady=(0, 6))

        # ── OR: load from file ────────────────────────────────────────────────
        ctk.CTkButton(
            panel,
            text="📂  Load from urls.txt",
            command=self._load_from_file,
            height=30,
            fg_color="transparent",
            border_color=BORDER,
            border_width=1,
            text_color=MUTED,
            hover_color="#1E293B",
            font=ctk.CTkFont(size=11),
            corner_radius=8,
        ).grid(row=3, column=0, padx=16, pady=(0, 10), sticky="w")

        # ── Divider ───────────────────────────────────────────────────────────
        ctk.CTkFrame(panel, height=1, fg_color=BORDER).grid(row=4, column=0, sticky="ew", padx=16, pady=4)

        # ── Section: Report Details ───────────────────────────────────────────
        self._section_label(panel, "📋  Report Details", row=5)

        self.app_name_var = ctk.StringVar()
        self.can_id_var   = ctk.StringVar()
        self.server_ip_var = ctk.StringVar()

        fields = [
            ("Application Name",         self.app_name_var,  "e.g. Net Banking Portal"),
            ("CAN ID",                   self.can_id_var,    "e.g. CAN-12345"),
            ("Server IP (optional)",     self.server_ip_var, "e.g. 10.0.0.1"),
        ]
        for i, (label, var, placeholder) in enumerate(fields):
            ctk.CTkLabel(
                panel,
                text=label,
                font=ctk.CTkFont(size=12),
                text_color=MUTED,
                anchor="w",
            ).grid(row=6 + i * 2, column=0, padx=18, pady=(6, 0), sticky="w")
            ctk.CTkEntry(
                panel,
                textvariable=var,
                placeholder_text=placeholder,
                fg_color="#0F172A",
                border_color=BORDER,
                border_width=1,
                text_color=TEXT,
                height=34,
                corner_radius=8,
            ).grid(row=7 + i * 2, column=0, padx=16, pady=(2, 0), sticky="ew")

        # ── Final comment ─────────────────────────────────────────────────────
        ctk.CTkLabel(
            panel,
            text="Final Assessment Comment",
            font=ctk.CTkFont(size=12),
            text_color=MUTED,
            anchor="w",
        ).grid(row=12, column=0, padx=18, pady=(8, 0), sticky="w")

        self.comment_box = ctk.CTkTextbox(
            panel,
            height=70,
            font=ctk.CTkFont(size=12),
            fg_color="#0F172A",
            border_color=BORDER,
            border_width=1,
            text_color=TEXT,
            corner_radius=8,
        )
        self.comment_box.grid(row=13, column=0, padx=16, pady=(2, 14), sticky="ew")

        # ── Divider ───────────────────────────────────────────────────────────
        ctk.CTkFrame(panel, height=1, fg_color=BORDER).grid(row=14, column=0, sticky="ew", padx=16, pady=2)

        # ── Scan button ───────────────────────────────────────────────────────
        self.scan_btn = ctk.CTkButton(
            panel,
            text="▶   Run Threat Scan",
            command=self._start_scan,
            height=46,
            fg_color=ORANGE,
            hover_color="#c95e10",
            text_color="white",
            font=ctk.CTkFont(size=15, weight="bold"),
            corner_radius=10,
        )
        self.scan_btn.grid(row=15, column=0, padx=16, pady=12, sticky="ew")

        # ── Progress bar ──────────────────────────────────────────────────────
        self.progress = ctk.CTkProgressBar(panel, fg_color=BORDER, progress_color=ORANGE, corner_radius=4)
        self.progress.set(0)
        self.progress.grid(row=16, column=0, padx=16, pady=(0, 14), sticky="ew")

    def _build_right_panel(self, parent):
        panel = ctk.CTkFrame(parent, fg_color=CARD, corner_radius=14, border_width=1, border_color=BORDER)
        panel.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)

        # Header row
        hdr = ctk.CTkFrame(panel, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=14, pady=(14, 6), sticky="ew")
        hdr.columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="📊  Scan Log",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            hdr,
            text="Clear",
            width=60,
            height=26,
            fg_color="transparent",
            border_color=BORDER,
            border_width=1,
            text_color=MUTED,
            hover_color=BG,
            font=ctk.CTkFont(size=11),
            corner_radius=6,
            command=self._clear_log,
        ).grid(row=0, column=1, sticky="e")

        self.log_box = ctk.CTkTextbox(
            panel,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG,
            text_color="#CBD5E1",
            border_width=0,
            corner_radius=10,
            wrap="word",
            state="disabled",
        )
        self.log_box.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

        # Status / result badge at bottom
        self.status_label = ctk.CTkLabel(
            panel,
            text="● Ready",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=GREEN,
            anchor="w",
        )
        self.status_label.grid(row=2, column=0, padx=16, pady=(0, 12), sticky="w")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _section_label(self, parent, text: str, row: int):
        ctk.CTkLabel(
            parent,
            text=text,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=TEXT,
            anchor="w",
        ).grid(row=row, column=0, padx=16, pady=(14, 0), sticky="w")

    def _append_log(self, msg: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def _show_about(self):
        about_window = ctk.CTkToplevel(self)
        about_window.title("About URL Threat Scanner")
        about_window.geometry("400x320")
        about_window.resizable(False, False)
        about_window.attributes("-topmost", True)
        about_window.configure(fg_color=BG)
        
        # Center the window
        about_window.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() // 2) - (400 // 2)
        y = self.winfo_y() + (self.winfo_height() // 2) - (320 // 2)
        about_window.geometry(f"+{x}+{y}")

        content = ctk.CTkFrame(about_window, fg_color=CARD, corner_radius=12, border_width=1, border_color=BORDER)
        content.pack(fill="both", expand=True, padx=16, pady=16)

        ctk.CTkLabel(content, text="🔐 URL Threat Scanner", font=ctk.CTkFont(size=18, weight="bold"), text_color=TEXT).pack(pady=(20, 10))
        
        info = [
            ("Version:", f"{APP_VERSION}"),
            ("Developed by:", "Kunal Kumar"),
            ("Developed date:", "Sept 2026"),
            ("Authorised to use:", "ICICI Bank Members"),
        ]

        for label, val in info:
            row = ctk.CTkFrame(content, fg_color="transparent")
            row.pack(fill="x", padx=30, pady=4)
            ctk.CTkLabel(row, text=label, font=ctk.CTkFont(size=12, weight="bold"), text_color=MUTED, width=120, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont(size=12), text_color=TEXT, anchor="w").pack(side="left")

        ctk.CTkButton(
            content, text="Close", width=100, height=32, 
            fg_color=NAVY, hover_color="#1e3a8a", 
            command=about_window.destroy
        ).pack(pady=(20, 10))

    def _load_from_file(self):
        path = filedialog.askopenfilename(
            title="Select URL list file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r") as f:
                content = f.read()
            self.url_box.delete("1.0", "end")
            self.url_box.insert("end", content)
            self._append_log(f"[*] Loaded URLs from: {path}")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    # ── Scan Orchestration ────────────────────────────────────────────────────
    def _start_scan(self):
        # Collect URLs
        raw = self.url_box.get("1.0", "end").strip()
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            messagebox.showwarning("No URLs", "Please enter at least one URL to scan.")
            return

        # Collect metadata
        app_name    = self.app_name_var.get().strip() or None
        can_id      = self.can_id_var.get().strip() or None
        server_ip   = self.server_ip_var.get().strip() or None
        final_comment = self.comment_box.get("1.0", "end").strip() or ""

        # Disable button, reset progress
        self.scan_btn.configure(state="disabled", text="⏳  Scanning…")
        self.progress.set(0)
        self.progress.start()
        self.status_label.configure(text="● Scanning…", text_color=ORANGE)
        self._clear_log()
        self._append_log(f"[*] Starting scan for {len(urls)} URL(s)…")

        # Run in background thread so UI stays responsive
        threading.Thread(
            target=self._run_scan,
            args=(urls, app_name, can_id, server_ip, final_comment),
            daemon=True,
        ).start()

    def _run_scan(self, urls, app_name, can_id, server_ip, final_comment):
        try:
            from app.services.scanner import scan_urls_batch
            from app.services.pdf_report import generate_pdf_report

            self.after(0, self._append_log, f"[*] Scanning {len(urls)} URL(s) — respecting API rate limits…")
            results = scan_urls_batch(urls)
            self.after(0, self._append_log, f"[+] Scans complete for {len(results)} URL(s).")
            self.after(0, self._append_log, "[*] Generating PDF report…")

            pdf_bytes = generate_pdf_report(
                results,
                final_comment=final_comment,
                app_name=app_name,
                can_id=can_id,
                server_ip=server_ip,
            )

            # Ask user where to save
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_name = f"threat_report_{timestamp}.pdf"

            def _save_dialog():
                save_path = filedialog.asksaveasfilename(
                    title="Save Threat Report",
                    initialfile=default_name,
                    defaultextension=".pdf",
                    filetypes=[("PDF files", "*.pdf")],
                )
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(pdf_bytes)
                    self._append_log(f"[+] Report saved to: {save_path}")
                    self.status_label.configure(text="● Report Saved", text_color=GREEN)
                else:
                    self._append_log("[!] Save cancelled.")
                    self.status_label.configure(text="● Done (not saved)", text_color=MUTED)

            self.after(0, _save_dialog)

        except Exception as exc:
            self.after(0, self._append_log, f"[-] Error: {exc}")
            self.after(0, self.status_label.configure, {"text": f"● Error: {exc}", "text_color": RED})
        finally:
            self.after(0, self._scan_done)

    def _scan_done(self):
        self.progress.stop()
        self.progress.set(1)
        self.scan_btn.configure(state="normal", text="▶   Run Threat Scan")


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = ThreatScannerApp()
    app.mainloop()
