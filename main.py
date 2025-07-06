"""Main entry point for the Simple Secure Encryption Tool"""
import tkinter as tk
from ui import EncryptionApp


def main():
    """Main entry point for the GUI application"""
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
