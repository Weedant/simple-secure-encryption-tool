import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionCore:

    @staticmethod
    def get_key_from_password(password, salt=None):
        # Generate a random salt if none provided
        if salt is None:
            salt = os.urandom(16)

        # Create a key derivation function
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        # Derive and encode the key
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def _validate_file_paths(input_file, output_file, callback=None):
        # Check if input file exists and is readable
        # Check if output directory exists and is writable
        # Return status and any error message

        if not os.path.exists(input_file):
            if callback: callback("Error: Input file not found.")
            return False, "Input file not found. Please check the file path."

        if not os.access(input_file, os.R_OK):
            if callback: callback("Error: Cannot read input file.")
            return False, "Cannot read input file. Please check file permissions."

        # Check output directory
        output_dir = os.path.dirname(output_file) or '.'
        if not os.path.exists(output_dir):
            if callback: callback("Error: Output directory does not exist.")
            return False, "Output directory does not exist."

        if not os.access(output_dir, os.W_OK):
            if callback: callback("Error: Cannot write to output directory.")
            return False, "Cannot write to output directory. Please check permissions."

        return True, ""

    @staticmethod
    def encrypt_file(input_file, output_file, password, callback=None):
        """
        Encrypt a file with password protection.

        Args:
            input_file (str): Path to file to encrypt
            output_file (str): Path for encrypted output
            password (str): Encryption password
            callback (function, optional): Function for status updates

        Returns:
            tuple: (success, message)
        """
        # Validate file paths
        valid, error_msg = EncryptionCore._validate_file_paths(input_file, output_file, callback)
        if not valid:
            return False, error_msg

        try:
            input_filename = os.path.basename(input_file)
            output_filename = os.path.basename(output_file)

            # Read file data
            if callback: callback(f"Reading file {input_filename}...")
            with open(input_file, 'rb') as f:
                file_data = f.read()

            # Generate key and encrypt
            if callback: callback("Generating encryption key from password...")
            key, salt = EncryptionCore.get_key_from_password(password)

            cipher = Fernet(key)

            if callback: callback("Encrypting file data...")
            encrypted_data = cipher.encrypt(file_data)

            # Write encrypted data with salt
            if callback: callback(f"Writing encrypted data to {output_filename}...")
            with open(output_file, 'wb') as f:
                f.write(salt)  # First 16 bytes are salt
                f.write(encrypted_data)

            if callback: callback(f"✅ File encrypted successfully to {output_filename}")
            return True, f"File encrypted successfully to {output_filename}"

        except IOError as e:
            error_message = f"I/O error: {e.strerror}" if hasattr(e, 'strerror') else "I/O error occurred"
            if callback: callback(f"❌ {error_message}")
            return False, error_message
        except MemoryError:
            if callback: callback("❌ File too large to process.")
            return False, "File too large to process. The file exceeds available memory."
        except Exception as e:
            if callback: callback(f"❌ An unexpected error occurred: {str(e)}")
            return False, f"An unexpected error occurred during encryption: {str(e)}"

    @staticmethod
    def decrypt_file(input_file, output_file, password, callback=None):
        """
        Decrypt a previously encrypted file.

        Args:
            input_file (str): Path to encrypted file
            output_file (str): Path for decrypted output
            password (str): Decryption password
            callback (function, optional): Function for status updates

        Returns:
            tuple: (success, message)
        """
        # Validate file paths
        valid, error_msg = EncryptionCore._validate_file_paths(input_file, output_file, callback)
        if not valid:
            return False, error_msg

        # Check if file is large enough to contain salt
        if os.path.getsize(input_file) < 16:
            if callback: callback("❌ Input file is too small to be a valid encrypted file.")
            return False, "Input file is too small to be a valid encrypted file."

        try:
            input_filename = os.path.basename(input_file)
            output_filename = os.path.basename(output_file)

            # Read encrypted data and salt
            if callback: callback(f"Reading encrypted file {input_filename}...")
            with open(input_file, 'rb') as f:
                salt = f.read(16)  # First 16 bytes are salt
                encrypted_data = f.read()  # Rest is encrypted data

            # Generate key for decryption
            if callback: callback("Generating decryption key from password...")
            key, _ = EncryptionCore.get_key_from_password(password, salt)

            cipher = Fernet(key)

            # Attempt decryption
            if callback: callback("Decrypting file data...")
            try:
                decrypted_data = cipher.decrypt(encrypted_data)
            except Exception:
                if callback: callback("❌ Decryption failed. Incorrect password or corrupted file.")
                return False, "Decryption failed. This could be due to an incorrect password or a corrupted file."

            # Write decrypted data
            if callback: callback(f"Writing decrypted data to {output_filename}...")
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)

            if callback: callback(f"✅ File decrypted successfully to {output_filename}")
            return True, f"File decrypted successfully to {output_filename}"

        except IOError as e:
            error_message = f"I/O error: {e.strerror}" if hasattr(e, 'strerror') else "I/O error occurred"
            if callback: callback(f"❌ {error_message}")
            return False, error_message
        except MemoryError:
            if callback: callback("❌ File too large to process.")
            return False, "File too large to process. The file exceeds available memory."
        except Exception as e:
            if callback: callback(f"❌ An unexpected error occurred: {str(e)}")
            return False, f"An unexpected error occurred during decryption: {str(e)}"
