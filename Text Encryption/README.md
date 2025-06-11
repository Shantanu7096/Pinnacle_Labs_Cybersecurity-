# 🔐 Text Encryption Tool

A Python-based encryption tool using AES, DES, and RSA algorithms with an interactive Tkinter GUI. Supports multi-language options, dark mode, drag-and-drop file input, password strength indication, and tooltips for guidance. Securely encrypt and decrypt text with ease.


## 🚀 Features
- **Multi-language support** (English & Hindi)
- **AES, DES & RSA Encryption** with real-time validation
- **Dark mode toggle** for better readability
- **Drag & Drop** file/text input support
- **Password strength indicator**
- **Tooltips** for user guidance


## 📜 Technologies Used
- **Python (Tkinter)** – UI development
- **Cryptography (AES, DES, RSA)** – Secure encryption
- **TkinterDnD** – Drag & Drop support



## 🙌 Acknowledgements

- **[Tkinter Documentation](https://docs.python.org/3/library/tkinter.html)** – Official reference for building interactive GUIs in Python.
- **[Cryptography Library](https://cryptography.io/en/latest/)** – Used for implementing AES, DES, and RSA encryption.
- **MDN Web Docs** – Helpful resources for security and best practices in encryption.
- **Users & Testers** – Thanks to everyone who tested and provided valuable feedback! 🚀

## 🎨 Color Reference

This tool uses the following color scheme:

| **Color** | **Hex Code** | **Usage** |
|-----------|------------|-----------|
| **Deep Blue** | `#1976D2` | Primary button background |
| **Dark Green** | `#388E3C` | Decrypt button background |
| **Red** | `#E53935` | Weak password indicator, Clear button |
| **Yellow** | `#FBC02D` | Moderate password strength indicator |
| **Dark Gray** | `#23272E` | Dark mode background |
| **Light Gray** | `#E3EAF2` | Default frame background |
| **White** | `#FFFFFF` | Text input fields & button text |

This ensures consistent UI styling across **light and dark modes**.

## Deployment

To run this project

```bash
  python text_encryption.py
```


## 📸 Screenshot

![image](https://github.com/user-attachments/assets/b021ee17-dea3-4c58-a537-41debc9d823e)

## ⚡ Optimizations

Here are some potential enhancements for future improvements:

- **Improve Encryption Efficiency** – Optimize the AES/DES functions to reduce computational overhead.
- **Enhance UI/UX** – Add more interactive animations and a dynamic theme switcher.
- **Optimize Performance** – Reduce unnecessary computations and improve response time for encryption/decryption.
- **Multi-threading Support** – Implement threading to ensure smooth UI experience during encryption.
- **Extend Security Features** – Integrate password strength analysis using libraries like **Zxcvbn**.
- **Cloud API Support** – Provide an option for **secure remote encryption** via an API.
- **Mobile Compatibility** – Adapt the UI for **touch-friendly** mobile and tablet usage.
## ❓ FAQ

### 🔹 How does the text encryption tool work?
This tool encrypts and decrypts messages using **AES, DES, and RSA** encryption algorithms. It provides real-time feedback and ensures secure encryption.

### 🔹 What encryption algorithms are supported?
The tool supports **AES (Advanced Encryption Standard)**, **DES (Data Encryption Standard)**, and **RSA (Rivest-Shamir-Adleman)**.

### 🔹 Do I need a key for encryption?
- **AES & DES** require a key (recommended **at least 8 characters**).
- **RSA** does not require a user-entered key since it uses **public/private key encryption**.

### 🔹 Is my data stored anywhere?
No, the encryption and decryption happen **locally** within your device. The tool does not store or send any sensitive data.

### 🔹 How can I improve password security?
- Use **longer passwords** (at least 12–16 characters).
- Include **uppercase, lowercase, numbers, and symbols**.
- Enable **multi-factor authentication (MFA)**.
- Avoid using **common or easily guessable passwords**.

### 🔹 Can I use this tool offline?
Yes! Since it's built with **Python Tkinter**, you can run it locally without an internet connection.

### 🔹 How do I change the tool's language?
The tool supports **English and Hindi**. You can select your preferred language from the dropdown menu in the UI.

## 🛣️ Roadmap

### ✅ Completed Features
- Multi-language support (English & Hindi)
- AES, DES, and RSA encryption/decryption
- Drag & drop file/text input support
- Password strength indicator
- Dark mode toggle
- Tooltips for user guidance

### 🔜 Upcoming Features
- **Customizable Encryption Settings** – Allow users to adjust encryption strength.
- **Integration with APIs** – Check for breached passwords using **Have I Been Pwned**.
- **Multi-threading Support** – Improve performance during encryption/decryption operations.
- **Mobile-Friendly UI** – Adapt the tool for tablets and smartphones.
- **Cloud Encryption Option** – Provide secure remote encryption via a cloud-based API.

### 🚀 Future Enhancements
- **AI-powered Encryption Suggestions** – Smart recommendations based on password security.
- **File Encryption Support** – Encrypt entire files instead of just text.
- **Security Audits & Reports** – Generate detailed encryption strength reports.
- **Integration with Password Managers** – Securely store encrypted passwords.

## 📚 Appendix

### 🔹 Supported Encryption Algorithms
- **AES (Advanced Encryption Standard)** – Symmetric encryption for secure data.
- **DES (Data Encryption Standard)** – Older encryption method, now less secure.
- **RSA (Rivest-Shamir-Adleman)** – Asymmetric encryption using public/private key pairs.

### 🔹 Useful Security Resources
- [OWASP Password Security Guidelines](https://owasp.org/www-project-password-cheat-sheet/)
- [Have I Been Pwned](https://haveibeenpwned.com/) – Check for compromised passwords.
- [Cryptography in Python](https://cryptography.io/en/latest/) – Official documentation for encryption libraries.

### 🔹 Additional Notes
- Ensure encryption keys are **strong and unique** to prevent brute-force attacks.
- Use **multi-factor authentication** wherever possible for added security.
- Encryption strength may vary based on **key length and complexity**.

## 🛠 Installation

### 🔹 Prerequisites
Ensure you have the following installed:
- **Python 3.x** (Recommended: 3.8 or later)
- Required libraries: `tkinter`, `tkinterdnd2`, `cryptography`
- (Optional) **PyInstaller** for creating an executable file
  
## 👤 Author

- **Harshwardhan Patil** – Developer & Creator of Text Encryption Tool
- GitHub: [@Shantanu7096](https://github.com/Shantanu7096)
- Email: skpatil6396@gmail.com
