print("Script started")
import tkinter as tk
from tkinter import ttk, messagebox
from aes_encryption import aes_encrypt, aes_decrypt
from des_encryption import des_encrypt, des_decrypt
from rsa_encryption import generate_keys, rsa_encrypt, rsa_decrypt

public_key, private_key = generate_keys()

def encrypt():
    algo = algo_var.get() 
    msg = message_input.get()
    key = key_input.get()
    if not msg:
        status_var.set("Please enter a message to encrypt.")
        return
    try:
        if algo == "AES":
            if not key:
                messagebox.showerror("Error", "Key is required for AES encryption.")
                return
            if len(key) < 8:
                messagebox.showwarning("Weak Key", "AES key should be at least 8 characters.")
            output.set(aes_encrypt(msg, key))
        elif algo == "DES":
            if not key:
                messagebox.showerror("Error", "Key is required for DES encryption.")
                return
            if len(key) < 8:
                messagebox.showwarning("Weak Key", "DES key should be at least 8 characters.")
            output.set(des_encrypt(msg, key))
        elif algo == "RSA":
            encrypted = rsa_encrypt(msg, public_key)
            output.set(encrypted.hex())
        status_var.set("Encryption successful!")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))
        status_var.set("Encryption failed.")

def decrypt():
    algo = algo_var.get()
    enc = output.get()
    key = key_input.get()
    if not enc:
        status_var.set("No encrypted text to decrypt.")
        return
    try:
        if algo == "AES":
            if not key:
                messagebox.showerror("Error", "Key is required for AES decryption.")
                return
            decrypted.set(aes_decrypt(enc, key))
        elif algo == "DES":
            if not key:
                messagebox.showerror("Error", "Key is required for DES decryption.")
                return
            decrypted.set(des_decrypt(enc, key))
        elif algo == "RSA":
            try:
                decrypted.set(rsa_decrypt(bytes.fromhex(enc), private_key))
            except ValueError:
                messagebox.showerror("Decryption Error", "Invalid encrypted text format for RSA.")
        status_var.set("Decryption successful!")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        status_var.set("Decryption failed.")

def on_algo_change(event=None):
    if algo_var.get() == "RSA":
        key_entry.config(state="disabled", show="")
        key_input.set("")
    else:
        key_entry.config(state="normal", show="*")

def clear_fields():
    message_input.set("")
    key_input.set("")
    output.set("")
    decrypted.set("")
    status_var.set("Cleared all fields.")

def copy_encrypted():
    if output.get():
        root.clipboard_clear()
        root.clipboard_append(output.get())
        status_var.set("Encrypted text copied to clipboard.")
    else:
        status_var.set("Nothing to copy.")

def copy_decrypted():
    if decrypted.get():
        root.clipboard_clear()
        root.clipboard_append(decrypted.get())
        status_var.set("Decrypted text copied to clipboard.")
    else:
        status_var.set("Nothing to copy.")

def create_tooltip(widget, text):
    tooltip = tk.Toplevel(widget)
    tooltip.withdraw()
    tooltip.overrideredirect(True)
    label = tk.Label(tooltip, text=text, background="#ffffe0", relief="solid", borderwidth=1, font=("tahoma", "8", "normal"))
    label.pack()
    def enter(event):
        x = event.x_root + 10
        y = event.y_root + 10
        tooltip.geometry(f"+{x}+{y}")
        tooltip.deiconify()
    def leave(event):
        tooltip.withdraw()
    widget.bind("<Enter>", enter)
    widget.bind("<Leave>", leave)

def toggle_key_visibility():
    if key_entry.cget('show') == '*':
        key_entry.config(show='')
        view_key_btn.config(text="Hide")
    else:
        key_entry.config(show='*')
        view_key_btn.config(text="View")

# GUI Setup
root = tk.Tk()
root.title("Text Encryption Tool")
root.geometry("500x400")
root.resizable(False, False)
root.configure(bg="#f0f4f8")

# Variables
message_input = tk.StringVar()
key_input = tk.StringVar()
output = tk.StringVar()
decrypted = tk.StringVar()
algo_var = tk.StringVar(value="AES")
status_var = tk.StringVar(value="Ready.")

# Widgets
frame = tk.Frame(root, padx=20, pady=20, bg="#e3eaf2")
frame.pack(fill="both", expand=True)

label_fg = "#1a237e"
entry_bg = "#ffffff"

title = tk.Label(frame, text="Text Encryption Tool", bg="#e3eaf2", fg="#0d47a1", font=("Arial", 16, "bold"))
title.grid(row=0, column=0, columnspan=3, pady=(0, 15), sticky="ew")

# Message
tk.Label(frame, text="Message:", bg="#e3eaf2", fg=label_fg).grid(row=1, column=0, sticky="e", pady=5, padx=(0, 8))
msg_entry = tk.Entry(frame, textvariable=message_input, width=40, bg=entry_bg)
msg_entry.grid(row=1, column=1, columnspan=2, sticky="w", pady=5)
create_tooltip(msg_entry, "Enter the message you want to encrypt or decrypt.")

# Algorithm
tk.Label(frame, text="Algorithm:", bg="#e3eaf2", fg=label_fg).grid(row=2, column=0, sticky="e", pady=5, padx=(0, 8))
algo_combo = ttk.Combobox(frame, textvariable=algo_var, values=["AES", "DES", "RSA"], state="readonly", width=37)
algo_combo.grid(row=2, column=1, columnspan=2, sticky="w", pady=5)
algo_combo.bind("<<ComboboxSelected>>", on_algo_change)
create_tooltip(algo_combo, "Choose the encryption algorithm.")

# Key
tk.Label(frame, text="Key (if needed):", bg="#e3eaf2", fg=label_fg).grid(row=3, column=0, sticky="e", pady=5, padx=(0, 8))
key_entry = tk.Entry(frame, textvariable=key_input, width=32, bg=entry_bg, show="*")
key_entry.grid(row=3, column=1, sticky="w", pady=5)
create_tooltip(key_entry, "Enter the key (password) for AES or DES. Not needed for RSA.")

view_key_btn = tk.Button(frame, text="View", command=toggle_key_visibility, width=7, bg="#bdbdbd")
view_key_btn.grid(row=3, column=2, sticky="w", pady=5, padx=(8, 0))
create_tooltip(view_key_btn, "Show or hide the key.")

# Buttons
tk.Button(frame, text="Encrypt", command=encrypt, width=18, bg="#1976d2", fg="white", activebackground="#1565c0").grid(row=4, column=0, pady=15, padx=2)
tk.Button(frame, text="Decrypt", command=decrypt, width=18, bg="#388e3c", fg="white", activebackground="#2e7d32").grid(row=4, column=1, pady=15, padx=2)
tk.Button(frame, text="Clear", command=clear_fields, width=10, bg="#e53935", fg="white", activebackground="#b71c1c").grid(row=4, column=2, pady=15, padx=2)

# Encrypted Text
tk.Label(frame, text="Encrypted Text:", bg="#e3eaf2", fg=label_fg).grid(row=5, column=0, sticky="e", pady=5, padx=(0, 8))
enc_entry = tk.Entry(frame, textvariable=output, width=40, state="readonly", bg=entry_bg)
enc_entry.grid(row=5, column=1, sticky="w", pady=5)
tk.Button(frame, text="Copy", command=copy_encrypted, width=8, bg="#ffb300", fg="black").grid(row=5, column=2, sticky="w", padx=(8, 0))
create_tooltip(enc_entry, "This is the encrypted output. You can copy it.")

# Decrypted Text
tk.Label(frame, text="Decrypted Text:", bg="#e3eaf2", fg=label_fg).grid(row=6, column=0, sticky="e", pady=5, padx=(0, 8))
dec_entry = tk.Entry(frame, textvariable=decrypted, width=40, state="readonly", bg=entry_bg)
dec_entry.grid(row=6, column=1, sticky="w", pady=5)
tk.Button(frame, text="Copy", command=copy_decrypted, width=8, bg="#ffb300", fg="black").grid(row=6, column=2, sticky="w", padx=(8, 0))
create_tooltip(dec_entry, "This is the decrypted output. You can copy it.")

# Status Bar
status_bar = tk.Label(root, textvariable=status_var, bd=1, relief="sunken", anchor="w", bg="#e3eaf2", fg="#333")
status_bar.pack(side="bottom", fill="x")

on_algo_change()  # Set initial key field state

root.mainloop()
