# Simple Secure Encryption Tool

A lightweight Python-based tool for file and text encryption/decryption using AES encryption. Supports both **Command-Line Interface (CLI)** and **Graphical User Interface (GUI)** with dark mode, logs, and user-friendly controls.

---

## Features

-  File encryption/decryption with password-based AES-128
-  Secure password input with salt & PBKDF2-HMAC
-  Dark/Light theme toggle in GUI
-  Real-time operation log with timestamps
-  Auto-clear password feature for enhanced security
-  Built with `cryptography`, `tkinter`, and multithreading

---

## GUI Preview

![demo1](https://github.com/user-attachments/assets/c958f4b8-3313-4ece-ad7b-1a5d8330bee2)

![demo2](https://github.com/user-attachments/assets/bc61fb82-8c42-40e2-833f-bf5aaa4a3c78)

![demo3](https://github.com/user-attachments/assets/9fe5e81e-a4a1-4f06-80db-93b0ca704d93)

---

##  Installation

```bash
git clone https://github.com/yourusername/simple-secure-encryption-tool.git
cd simple-secure-encryption-tool
pip install -r requirements.txt
```

---

##  Usage

### CLI (Command Line)

```bash
# Encrypt text
python core.py encrypt --text "Secret Message"

# Encrypt file
python core.py encrypt --input-file mydoc.txt --output-file mydoc.enc
```

### GUI

```bash
python main.py
```

---

##  License

MIT License – Feel free to use, modify, and contribute.

---

##  Author

**Vedant Tammewar**  
Cybersecurity Intern @ Ahir InfoTech  
MIT-WPU M.Tech Cybersecurity | Python Enthusiast | Cloud & Security

---

## 🌟 Star this repo if you found it useful!
