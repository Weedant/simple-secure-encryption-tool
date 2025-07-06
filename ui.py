"""User interface for the encryption tool"""
import os
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
from enum import Enum

from core import EncryptionCore
from utils import THEMES, Theme, format_log_message, get_filename_with_extension, APP_NAME, APP_VERSION


class OperationType(Enum):
    """Operation types for the application"""
    NONE = "none"
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"


class EncryptionApp:
    """Main GUI application for encryption/decryption"""

    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("800x600")
        self.root.minsize(600, 500)

        # Set default theme
        self.current_theme = Theme.LIGHT.value

        # User preferences
        self.auto_clear_password = tk.BooleanVar(value=False)

        self.setup_ui()
        self.current_operation = OperationType.NONE  # Track current operation
        self.apply_theme()

    def setup_ui(self):
        """Set up the user interface"""
        # Main frame
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self._create_password_section()
        self._create_file_selection_section()
        self._create_action_buttons()
        self._create_log_section()
        self._create_status_bar()

        # Initial log message
        self.log(f"Welcome to {APP_NAME} v{APP_VERSION}")
        self.log("Please select a file and enter a password to begin.")
        self.log("Dark mode and auto-clear password features are available.")

    def _create_password_section(self):
        """Create password input section"""
        # Password frame
        password_frame = ttk.LabelFrame(self.main_frame, text="Password", padding="10")
        password_frame.pack(fill=tk.X, pady=5)

        # Password entry
        ttk.Label(password_frame, text="Enter Password:").pack(side=tk.LEFT, padx=5)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)

        # Show/hide password button
        self.show_password = tk.BooleanVar(value=False)
        self.show_password_btn = ttk.Checkbutton(
            password_frame,
            text="Show",
            variable=self.show_password,
            command=self.toggle_password_visibility
        )
        self.show_password_btn.pack(side=tk.LEFT, padx=5)

        # Auto-clear password checkbox
        self.auto_clear_password_btn = ttk.Checkbutton(
            password_frame,
            text="Auto-clear password after operation",
            variable=self.auto_clear_password
        )
        self.auto_clear_password_btn.pack(side=tk.LEFT, padx=10)

    def _create_file_selection_section(self):
        """Create file selection section"""
        # File selection frame
        file_frame = ttk.LabelFrame(self.main_frame, text="File Selection", padding="10")
        file_frame.pack(fill=tk.X, pady=5)

        # Input file
        input_file_frame = ttk.Frame(file_frame)
        input_file_frame.pack(fill=tk.X, pady=2)
        ttk.Label(input_file_frame, text="Input File:").pack(side=tk.LEFT, padx=5)
        self.input_file_var = tk.StringVar()
        self.input_file_display_var = tk.StringVar()  # For displaying just filename
        self.input_file_entry = ttk.Entry(input_file_frame, textvariable=self.input_file_display_var, width=40)
        self.input_file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.browse_input_btn = ttk.Button(input_file_frame, text="Browse", command=self.browse_input_file)
        self.browse_input_btn.pack(side=tk.LEFT, padx=5)

        # Output file
        output_file_frame = ttk.Frame(file_frame)
        output_file_frame.pack(fill=tk.X, pady=2)
        ttk.Label(output_file_frame, text="Output File:").pack(side=tk.LEFT, padx=5)
        self.output_file_var = tk.StringVar()
        self.output_file_display_var = tk.StringVar()  # For displaying just filename
        self.output_file_entry = ttk.Entry(output_file_frame, textvariable=self.output_file_display_var, width=40)
        self.output_file_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.browse_output_btn = ttk.Button(output_file_frame, text="Browse", command=self.browse_output_file)
        self.browse_output_btn.pack(side=tk.LEFT, padx=5)

    def _create_action_buttons(self):
        """Create action buttons"""
        # Action buttons frame
        action_frame = ttk.Frame(self.main_frame)
        action_frame.pack(fill=tk.X, pady=10)

        # Encrypt/Decrypt buttons
        self.encrypt_btn = ttk.Button(
            action_frame,
            text="Encrypt File",
            command=lambda: self.process_file(OperationType.ENCRYPT.value)
        )
        self.encrypt_btn.pack(side=tk.LEFT, padx=5)

        self.decrypt_btn = ttk.Button(
            action_frame,
            text="Decrypt File",
            command=lambda: self.process_file(OperationType.DECRYPT.value)
        )
        self.decrypt_btn.pack(side=tk.LEFT, padx=5)

        # Theme toggle button
        self.theme_button = ttk.Button(action_frame, text="Toggle Dark Mode", command=self.toggle_theme)
        self.theme_button.pack(side=tk.LEFT, padx=20)

        # Clear button
        self.clear_btn = ttk.Button(action_frame, text="Clear", command=self.clear_fields)
        self.clear_btn.pack(side=tk.RIGHT, padx=5)

    def _create_log_section(self):
        """Create log section"""
        # Log section
        log_frame = ttk.LabelFrame(self.main_frame, text="Operation Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # Log text widget
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED)  # Read-only

    def _create_status_bar(self):
        """Create status bar"""
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def apply_theme(self):
        """Apply the current theme to all widgets"""
        theme = THEMES[self.current_theme]

        # Configure ttk style
        style = ttk.Style()
        style.theme_use('clam')  # Use 'clam' theme as base for better customization

        # Configure colors for ttk widgets
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])

        # Button styling with proper hover effects
        style.configure('TButton',
                        background=theme['button_bg'],
                        foreground=theme['button_fg'])
        style.map('TButton',
                  background=[('active', theme['button_active_bg']),
                              ('pressed', theme['button_active_bg'])],
                  foreground=[('active', theme['button_active_fg']),
                              ('pressed', theme['button_active_fg'])])

        # Checkbox styling with proper hover effects
        style.configure('TCheckbutton',
                        background=theme['bg'],
                        foreground=theme['fg'])
        style.map('TCheckbutton',
                  background=[('active', theme['bg'])],
                  foreground=[('active', theme['fg'])])

        # Entry styling
        style.configure('TEntry',
                        fieldbackground=theme['text_bg'],
                        foreground=theme['text_fg'])

        # LabelFrame styling
        style.configure('TLabelframe',
                        background=theme['bg'],
                        foreground=theme['fg'])
        style.configure('TLabelframe.Label',
                        background=theme['bg'],
                        foreground=theme['fg'])

        # Configure root and main containers
        self.root.configure(bg=theme['bg'])

        # Configure text widgets
        self.log_text.config(
            bg=theme['log_bg'],
            fg=theme['log_fg'],
            insertbackground=theme['fg']
        )

        # Status bar
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])

        # Update theme button text
        if self.current_theme == Theme.LIGHT.value:
            self.theme_button.config(text="Toggle Dark Mode")
        else:
            self.theme_button.config(text="Toggle Light Mode")

        # Log the theme change
        self.log(f"Theme changed to {self.current_theme} mode")

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.current_theme = Theme.DARK.value if self.current_theme == Theme.LIGHT.value else Theme.LIGHT.value
        self.apply_theme()

    def browse_input_file(self):
        """Open file dialog to select input file"""
        filename = filedialog.askopenfilename(title="Select Input File")
        if filename:
            self.input_file_var.set(filename)
            self.input_file_display_var.set(os.path.basename(filename))

            # Auto-generate output filename
            is_encrypted = filename.endswith('.enc')
            output_filename = get_filename_with_extension(filename, is_encrypted)
            self.output_file_var.set(output_filename)
            self.output_file_display_var.set(os.path.basename(output_filename))

            self.log(f"Input file selected: {os.path.basename(filename)}")

            # Set the appropriate button state based on file extension
            if is_encrypted:
                self.current_operation = OperationType.DECRYPT
                self.update_button_states()
            else:
                self.current_operation = OperationType.ENCRYPT
                self.update_button_states()

    def browse_output_file(self):
        """Open file dialog to select output file"""
        filename = filedialog.asksaveasfilename(title="Select Output File")
        if filename:
            self.output_file_var.set(filename)
            self.output_file_display_var.set(os.path.basename(filename))
            self.log(f"Output file selected: {os.path.basename(filename)}")

    def process_file(self, action):
        """Process file for encryption or decryption"""
        input_file = self.input_file_var.get()
        output_file = self.output_file_var.get()
        password = self.password_var.get()

        # Validate inputs
        if not input_file:
            messagebox.showerror("Error", "Please select an input file.")
            return
        if not output_file:
            messagebox.showerror("Error", "Please specify an output file.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        # Update status and button states
        self.current_operation = OperationType(action)
        self.update_button_states()
        self.status_var.set(f"{action.capitalize()}ing file...")

        # Start processing in a separate thread
        self.log(f"Starting {action} operation...")
        threading.Thread(
            target=self._process_file_thread,
            args=(action, input_file, output_file, password),
            daemon=True
        ).start()

    def update_button_states(self):
        """Update button states based on current operation"""
        if self.current_operation == OperationType.ENCRYPT:
            self.encrypt_btn.config(state=tk.NORMAL)
            self.decrypt_btn.config(state=tk.DISABLED)
            self.clear_btn.config(state=tk.NORMAL)
        elif self.current_operation == OperationType.DECRYPT:
            self.encrypt_btn.config(state=tk.DISABLED)
            self.decrypt_btn.config(state=tk.NORMAL)
            self.clear_btn.config(state=tk.NORMAL)
        else:  # No operation or processing completed
            self.encrypt_btn.config(state=tk.NORMAL)
            self.decrypt_btn.config(state=tk.NORMAL)
            self.clear_btn.config(state=tk.NORMAL)

    def _process_file_thread(self, action, input_file, output_file, password):
        """Thread function to process file without blocking GUI"""
        try:
            if action == OperationType.ENCRYPT.value:
                success, message = EncryptionCore.encrypt_file(
                    input_file, output_file, password, callback=self.log
                )
            else:  # decrypt
                success, message = EncryptionCore.decrypt_file(
                    input_file, output_file, password, callback=self.log
                )

            # Reset current operation and update status
            def update_ui():
                self.current_operation = OperationType.NONE
                self.update_button_states()
                self.status_var.set("Ready")

                # Auto-clear password if option is selected
                if self.auto_clear_password.get() and success:
                    self.password_var.set("")
                    self.log("Password cleared automatically")

                # Show result message
                if success:
                    messagebox.showinfo("Success", message)
                else:
                    messagebox.showerror("Error", message)

            # Ensure UI updates happen in the main thread
            self.root.after(0, update_ui)

        except Exception as e:
            self.log(f"❌ Error: {str(e)}")

            def show_error():
                self.current_operation = OperationType.NONE
                self.update_button_states()
                self.status_var.set("Error occurred")
                messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")

            self.root.after(0, show_error)

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def clear_fields(self):
        """Clear all input fields"""
        self.password_var.set("")
        self.input_file_var.set("")
        self.input_file_display_var.set("")
        self.output_file_var.set("")
        self.output_file_display_var.set("")
        self.current_operation = OperationType.NONE
        self.update_button_states()
        self.log("Fields cleared")

    def log(self, message):
        """Add message to log with timestamp"""
        log_entry = format_log_message(message)

        # Update log in main thread
        def update_log():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, log_entry)
            self.log_text.see(tk.END)  # Scroll to end
            self.log_text.config(state=tk.DISABLED)

        # Ensure UI updates happen in the main thread
        if threading.current_thread() is threading.main_thread():
            update_log()
        else:
            self.root.after(0, update_log)