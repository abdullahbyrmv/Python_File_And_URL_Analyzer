import os
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox, simpledialog
from threading import Thread

from main import (
    FileandURLAnalysisApp,
    scan_by_hash,
    scan_by_url,
    scan_by_ip,
)

root = tk.Tk()
root.title("Python File, Hash, URL, and IP Analyzer")
root.state("zoomed")
root.geometry("1920x1080")


api_key_var = tk.StringVar(value=os.getenv("VirusTotal_API_KEY"))

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=25)
output_box.pack(pady=10)

import builtins  # noqa: E402

original_print = builtins.print


def gui_print(*args, **kwargs):
    message = " ".join(map(str, args)) + "\n"
    output_box.insert(tk.END, message)
    output_box.see(tk.END)
    original_print(*args, **kwargs)


builtins.print = gui_print


def analyze_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    if not os.path.isfile(file_path):
        messagebox.showerror("Error", "File does not exist.")
        return

    def run_scan():
        FileandURLAnalysisApp(file_path, api_key_var.get()).run()
        print("\n" * 5)
        print(
            "\n----------------------------------------------------------------------------------------------------\n"
        )

    Thread(target=run_scan).start()


def analyze_by_hash():
    hash_value = simpledialog.askstring("Scan by Hash", "Enter file hash:")

    # Check if user cancelled or entered empty string
    if hash_value is None or not hash_value.strip():
        messagebox.showerror("Error", "Hash value cannot be empty.")
        return

    hash_value = hash_value.strip()

    def run_scan():
        scan_by_hash(api_key_var.get(), hash_value)
        print("\n" * 5)
        print(
            "\n----------------------------------------------------------------------------------------------------\n"
        )

    Thread(target=run_scan).start()


def analyze_by_url():
    url = simpledialog.askstring("Scan by URL", "Enter URL to analyze:")

    if url is None or not url.strip():
        messagebox.showerror("Error", "URL cannot be empty.")
        return

    url = url.strip()

    def run_scan():
        scan_by_url(api_key_var.get(), url)
        print("\n" * 5)
        print(
            "\n----------------------------------------------------------------------------------------------------\n"
        )

    Thread(target=run_scan).start()


def analyze_by_ip():
    ip_address = simpledialog.askstring("Scan by IP", "Enter IP address:")

    if ip_address is None or not ip_address.strip():
        messagebox.showerror("Error", "IP address cannot be empty.")
        return

    ip_address = ip_address.strip()

    def run_scan():
        scan_by_ip(api_key_var.get(), ip_address)
        print("\n" * 5)
        print(
            "\n----------------------------------------------------------------------------------------------------\n"
        )

    Thread(target=run_scan).start()


frame_controls = tk.Frame(root)
frame_controls.pack(pady=5)


tk.Button(
    frame_controls, text="Analyze File", command=analyze_file, width=15, height=3
).grid(row=0, column=0, pady=15, padx=15, sticky="ew")
tk.Button(
    frame_controls, text="Analyze Hash", command=analyze_by_hash, width=15, height=3
).grid(row=0, column=1, pady=15, padx=15, sticky="ew")
tk.Button(
    frame_controls, text="Analyze URL", command=analyze_by_url, width=15, height=3
).grid(row=1, column=0, pady=15, padx=15, sticky="ew")
tk.Button(
    frame_controls, text="Analyze IP Address", command=analyze_by_ip, width=15, height=3
).grid(row=1, column=1, pady=15, padx=15, sticky="ew")

tk.Button(
    frame_controls,
    text="Exit the Application",
    command=root.destroy,
    fg="white",
    bg="red",
    width=15,
    height=3,
).grid(row=2, column=0, columnspan=2, pady=10, sticky="ew")

root.mainloop()
