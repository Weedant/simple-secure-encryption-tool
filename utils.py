"""Utilities and shared constants for the encryption tool"""
from enum import Enum
import os
import time

# Application constants
APP_NAME = "Simple Secure Encryption Tool"
APP_VERSION = "1.3.2"


class Theme(Enum):
    """Theme enum for application"""
    LIGHT = "light"
    DARK = "dark"


# Define colors for light and dark themes
THEMES = {
    Theme.LIGHT.value: {
        "bg": "#f0f0f0",
        "fg": "black",
        "text_bg": "white",
        "text_fg": "black",
        "button_bg": "#e0e0e0",
        "button_fg": "black",
        "button_active_bg": "#d0d0d0",
        "button_active_fg": "black",
        "highlight_bg": "#d0d0d0",
        "log_bg": "white",
        "log_fg": "black"
    },
    Theme.DARK.value: {
        "bg": "#2d2d2d",
        "fg": "white",
        "text_bg": "#3d3d3d",
        "text_fg": "white",
        "button_bg": "#444444",
        "button_fg": "white",
        "button_active_bg": "#555555",
        "button_active_fg": "white",
        "highlight_bg": "#555555",
        "log_bg": "#2a2a2a",
        "log_fg": "#cccccc"
    }
}


def format_log_message(message):
    """Format log message with timestamp"""
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    return f"[{timestamp}] {message}\n"


def get_filename_with_extension(filename, is_encrypted=False):
    """Generate appropriate filename based on encryption status"""
    if is_encrypted and filename.endswith('.enc'):
        return filename[:-4] + '.dec'
    elif not is_encrypted and not filename.endswith('.enc'):
        return filename + '.enc'
    return filename


def validate_file_path(file_path, check_write=False):
    """Validate if file path exists and is accessible"""
    if not file_path:
        return False, "No file path provided"

    # For input files
    if not check_write:
        if not os.path.exists(file_path):
            return False, "File not found"
        if not os.access(file_path, os.R_OK):
            return False, "File not readable"
        return True, "File is valid"

    # For output files
    else:
        output_dir = os.path.dirname(file_path) or '.'
        if not os.path.exists(output_dir):
            return False, "Output directory does not exist"
        if not os.access(output_dir, os.W_OK):
            return False, "Output directory not writable"
        return True, "Output path is valid"
