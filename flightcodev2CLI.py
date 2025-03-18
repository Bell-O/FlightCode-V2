#!/usr/bin/env python3
"""
FlightCode CLI - Secure File Encryption Tool
Version 2.0

A command-line interface for secure file encryption, decryption, and secure deletion
"""

import os
import sys
import getpass
import base64
import hashlib
import time
import random
import string
import argparse
import subprocess
from datetime import datetime
from typing import Optional, Tuple, Dict, Any
import json

try:
    import pyfiglet
    from colorama import Fore, Style, init
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.exceptions import InvalidTag
except ImportError:
    print("Error: Required dependencies not found.")
    print("Installing required packages...")
    
    # Define packages to install
    packages = ["cryptography", "argon2-cffi", "colorama", "pyfiglet"]
    
    for package in packages:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            print(f"Package {package} installed successfully.")
        except Exception as e:
            print(f"Error installing {package}: {e}")
            sys.exit(1)
    
    # Try importing again after installation
    import pyfiglet
    from colorama import Fore, Style, init
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from argon2.low_level import hash_secret_raw, Type
    from cryptography.exceptions import InvalidTag

# Initialize colorama
init(autoreset=True)

# Constants
APP_NAME = "FlightCode CLI"
APP_VERSION = "2.0"
FILE_EXTENSION = ".hee"
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".flightcode_config.json")


class CryptoService:
    """Handles all cryptographic operations"""
    
    # Improved parameters for better security
    SALT_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16
    KEY_SIZE = 32  # 256 bits for AES-256
    
    # Argon2 parameters (increased for better security)
    TIME_COST = 3
    MEMORY_COST = 2**18  # ~256MB
    PARALLELISM = 4
    
    @staticmethod
    def derive_key(password: str, salt: bytes, key_size: int = KEY_SIZE) -> bytes:
        """
        Derives an encryption key from a password using Argon2id
        
        Args:
            password: The user's password
            salt: Random salt for key derivation
            key_size: Size of the key to generate (default: 32 bytes for AES-256)
            
        Returns:
            Derived key as bytes
        """
        if key_size not in [16, 24, 32]:
            raise ValueError("Invalid key size. AES supports 16, 24, or 32 bytes.")
            
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=CryptoService.TIME_COST,
            memory_cost=CryptoService.MEMORY_COST,
            parallelism=CryptoService.PARALLELISM,
            hash_len=key_size,
            type=Type.ID,
        )
    
    @staticmethod
    def encrypt_data(data: bytes, password: str) -> bytes:
        """
        Encrypts data with AES-GCM
        
        Args:
            data: Data to encrypt
            password: User's password
            
        Returns:
            Encrypted data with metadata (salt + nonce + tag + ciphertext)
        """
        # Generate secure random values
        salt = os.urandom(CryptoService.SALT_SIZE)
        nonce = os.urandom(CryptoService.NONCE_SIZE)
        
        # Derive key from password
        key = CryptoService.derive_key(password, salt)
        
        # Encrypt data
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Add file metadata as associated data for authentication
        metadata = f"FlightCode v{APP_VERSION} - {datetime.now().isoformat()}".encode()
        encryptor.authenticate_additional_data(metadata)
        
        # Encrypt the data
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Get authentication tag
        tag = encryptor.tag
        
        # Format: salt + nonce + tag + metadata_length + metadata + ciphertext
        metadata_length = len(metadata).to_bytes(2, byteorder='big')
        return salt + nonce + tag + metadata_length + metadata + ciphertext
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
        """
        Decrypts data encrypted with AES-GCM
        
        Args:
            encrypted_data: Encrypted data with metadata
            password: User's password
            
        Returns:
            Decrypted data
            
        Raises:
            InvalidTag: If authentication fails (wrong password or corrupted data)
            ValueError: If the encrypted data format is invalid
        """
        if len(encrypted_data) < CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE + 2:
            raise ValueError("Invalid encrypted data format")
            
        # Extract components
        salt = encrypted_data[:CryptoService.SALT_SIZE]
        nonce = encrypted_data[CryptoService.SALT_SIZE:CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE]
        tag = encrypted_data[
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE:
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE
        ]
        
        # Extract metadata length and metadata
        metadata_length_bytes = encrypted_data[
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE:
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE + 2
        ]
        metadata_length = int.from_bytes(metadata_length_bytes, byteorder='big')
        
        metadata = encrypted_data[
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE + 2:
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE + 2 + metadata_length
        ]
        
        # Extract ciphertext
        ciphertext = encrypted_data[
            CryptoService.SALT_SIZE + CryptoService.NONCE_SIZE + CryptoService.TAG_SIZE + 2 + metadata_length:
        ]
        
        # Derive key from password and salt
        key = CryptoService.derive_key(password, salt)
        
        # Decrypt data
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Add metadata as associated data for authentication
        decryptor.authenticate_additional_data(metadata)
        
        # Decrypt the ciphertext
        return decryptor.update(ciphertext) + decryptor.finalize()


class FileHandler:
    """Handles file operations"""
    
    @staticmethod
    def read_file(file_path: str) -> bytes:
        """Reads a file and returns its contents as bytes"""
        with open(file_path, 'rb') as f:
            return f.read()
    
    @staticmethod
    def write_file(file_path: str, data: bytes) -> None:
        """Writes bytes to a file"""
        with open(file_path, 'wb') as f:
            f.write(data)
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> None:
        """
        Securely deletes a file by overwriting it with random data
        
        Args:
            file_path: Path to the file to delete
            passes: Number of overwrite passes (default: 3)
        """
        if not os.path.exists(file_path):
            return
            
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Perform secure deletion
        with open(file_path, 'wb') as f:
            for i in range(passes):
                # Seek to beginning of file
                f.seek(0)
                
                # Write random data
                f.write(os.urandom(file_size))
                
                # Flush to disk
                f.flush()
                os.fsync(f.fileno())
                
                # Progress indicator
                print(Fore.YELLOW + f"Pass {i+1}/{passes}: Overwriting with random data...")
        
        # Finally delete the file
        os.remove(file_path)
        print(Fore.GREEN + f"[+] File successfully shredded!")


class ConfigManager:
    """Manages application configuration"""
    
    @staticmethod
    def load_config() -> Dict[str, Any]:
        """Loads configuration from file or returns defaults"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
            
        # Default configuration
        return {
            "secure_delete": True,
            "secure_delete_passes": 3,
            "recent_files": [],
            "last_directory": os.path.expanduser("~")
        }
    
    @staticmethod
    def save_config(config: Dict[str, Any]) -> None:
        """Saves configuration to file"""
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f)
        except Exception as e:
            print(Fore.RED + f"[!] Error saving configuration: {e}")
    
    @staticmethod
    def add_recent_file(file_path: str) -> None:
        """Adds a file to recent files list"""
        config = ConfigManager.load_config()
        
        # Update recent files
        if "recent_files" not in config:
            config["recent_files"] = []
            
        # Add to recent files if not already there
        if file_path not in config["recent_files"]:
            config["recent_files"].insert(0, file_path)
            
        # Keep only the 10 most recent files
        config["recent_files"] = config["recent_files"][:10]
        
        # Update last directory
        config["last_directory"] = os.path.dirname(file_path)
        
        # Save updated config
        ConfigManager.save_config(config)


class PasswordGenerator:
    """Generates secure random passwords"""
    
    @staticmethod
    def generate_password(
        length: int = 16,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True
    ) -> str:
        """
        Generates a secure random password
        
        Args:
            length: Length of the password (default: 16)
            use_uppercase: Include uppercase letters (default: True)
            use_lowercase: Include lowercase letters (default: True)
            use_digits: Include digits (default: True)
            use_symbols: Include symbols (default: True)
            
        Returns:
            Generated password
        """
        # Define character sets
        chars = ""
        if use_uppercase:
            chars += string.ascii_uppercase
        if use_lowercase:
            chars += string.ascii_lowercase
        if use_digits:
            chars += string.digits
        if use_symbols:
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
            
        if not chars:
            raise ValueError("At least one character set must be enabled")
            
        # Generate password
        return ''.join(random.choice(chars) for _ in range(length))


def display_banner():
    """Displays the application banner"""
    fig = pyfiglet.Figlet(font="slant")
    print(Fore.RED + fig.renderText("FlightCode"))
    print(Fore.YELLOW + f"Version {APP_VERSION} - Your Security, My Priority")
    print(Fore.YELLOW + "by Bell (github.com/Bell-O)")
    print(Fore.CYAN + "=" * 60)


def list_files(directory=None):
    """
    Lists all files in the specified directory or current directory.
    
    Args:
        directory: Directory to list files from (default: current directory)
        
    Returns:
        List of file paths
    """
    if directory is None:
        directory = os.getcwd()
    
    try:
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        
        if not files:
            print(Fore.RED + f"[!] No files found in {directory}")
            return None
        
        print(Fore.CYAN + f"\nFiles in {directory}:")
        for idx, file in enumerate(files):
            file_size = os.path.getsize(os.path.join(directory, file))
            size_str = format_file_size(file_size)
            is_encrypted = file.endswith(FILE_EXTENSION)
            
            if is_encrypted:
                print(Fore.GREEN + f"  {idx + 1}. {file} ({size_str}) [ENCRYPTED]")
            else:
                print(Fore.CYAN + f"  {idx + 1}. {file} ({size_str})")
        
        return [os.path.join(directory, f) for f in files]
    
    except Exception as e:
        print(Fore.RED + f"[!] Error listing files: {e}")
        return None


def format_file_size(size_bytes):
    """Formats file size in human-readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def select_file(files):
    """
    Allows the user to select a file by number.
    
    Args:
        files: List of file paths
        
    Returns:
        Selected file path or None if selection failed
    """
    if not files:
        return None
    
    try:
        file_index = int(input(Fore.YELLOW + "\n[?] Select a file number (or 0 to cancel): ")) - 1
        
        if file_index == -1:
            print(Fore.YELLOW + "[*] Operation cancelled.")
            return None
        
        if 0 <= file_index < len(files):
            return files[file_index]
        else:
            print(Fore.RED + "[!] Invalid file number. Please try again.")
            return None
    except ValueError:
        print(Fore.RED + "[!] Please enter a valid number.")
        return None


def encrypt_file():
    """Encrypts a file selected by the user"""
    # List files
    files = list_files()
    if not files:
        return
    
    # Select file
    file_path = select_file(files)
    if not file_path:
        return
    
    # Get output path
    default_output = f"{file_path}{FILE_EXTENSION}"
    output_path = input(Fore.YELLOW + f"[?] Output file path (default: {default_output}): ").strip()
    if not output_path:
        output_path = default_output
    
    # Check if output file already exists
    if os.path.exists(output_path):
        response = input(Fore.YELLOW + f"[?] File {output_path} already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print(Fore.YELLOW + "[*] Operation cancelled.")
            return
    
    # Get password
    password = getpass.getpass(Fore.YELLOW + "[?] Enter password: ")
    confirm_password = getpass.getpass(Fore.YELLOW + "[?] Confirm password: ")
    
    if password != confirm_password:
        print(Fore.RED + "[!] Passwords do not match.")
        return
    
    # Ask about secure deletion
    secure_delete = input(Fore.YELLOW + "[?] Securely delete original file after encryption? (y/n): ").lower() == 'y'
    
    try:
        print(Fore.YELLOW + f"[*] Reading file: {file_path}")
        file_data = FileHandler.read_file(file_path)
        
        print(Fore.YELLOW + "[*] Encrypting data...")
        encrypted_data = CryptoService.encrypt_data(file_data, password)
        
        print(Fore.YELLOW + f"[*] Writing encrypted file: {output_path}")
        FileHandler.write_file(output_path, encrypted_data)
        
        # Add to recent files
        ConfigManager.add_recent_file(output_path)
        
        # Securely delete original if requested
        if secure_delete:
            print(Fore.YELLOW + "[*] Securely deleting original file...")
            FileHandler.secure_delete(file_path)
        
        print(Fore.GREEN + f"[+] File encrypted successfully: {output_path}")
        
    except Exception as e:
        print(Fore.RED + f"[!] Error during encryption: {e}")


def decrypt_file():
    """Decrypts a file selected by the user"""
    # List files
    files = list_files()
    if not files:
        return
    
    # Filter encrypted files
    encrypted_files = [f for f in files if os.path.basename(f).endswith(FILE_EXTENSION)]
    
    if not encrypted_files:
        print(Fore.RED + "[!] No encrypted files found.")
        response = input(Fore.YELLOW + "[?] Show all files anyway? (y/n): ")
        if response.lower() == 'y':
            pass
        else:
            return
    else:
        files = encrypted_files
        print(Fore.CYAN + "\nEncrypted files:")
        for idx, file in enumerate(files):
            file_size = os.path.getsize(file)
            size_str = format_file_size(file_size)
            print(Fore.GREEN + f"  {idx + 1}. {os.path.basename(file)} ({size_str})")
    
    # Select file
    file_path = select_file(files)
    if not file_path:
        return
    
    # Get output path
    default_output = file_path
    if default_output.endswith(FILE_EXTENSION):
        default_output = default_output[:-len(FILE_EXTENSION)]
    else:
        default_output = f"{default_output}.decrypted"
    
    output_path = input(Fore.YELLOW + f"[?] Output file path (default: {default_output}): ").strip()
    if not output_path:
        output_path = default_output
    
    # Check if output file already exists
    if os.path.exists(output_path):
        response = input(Fore.YELLOW + f"[?] File {output_path} already exists. Overwrite? (y/n): ")
        if response.lower() != 'y':
            print(Fore.YELLOW + "[*] Operation cancelled.")
            return
    
    # Get password
    password = getpass.getpass(Fore.YELLOW + "[?] Enter password: ")
    
    # Ask about secure deletion
    secure_delete = input(Fore.YELLOW + "[?] Securely delete encrypted file after decryption? (y/n): ").lower() == 'y'
    
    try:
        print(Fore.YELLOW + f"[*] Reading encrypted file: {file_path}")
        encrypted_data = FileHandler.read_file(file_path)
        
        print(Fore.YELLOW + "[*] Decrypting data...")
        try:
            decrypted_data = CryptoService.decrypt_data(encrypted_data, password)
        except InvalidTag:
            print(Fore.RED + "[!] Authentication failed: Invalid password or corrupted file.")
            return
        
        print(Fore.YELLOW + f"[*] Writing decrypted file: {output_path}")
        FileHandler.write_file(output_path, decrypted_data)
        
        # Add to recent files
        ConfigManager.add_recent_file(output_path)
        
        # Securely delete encrypted file if requested
        if secure_delete:
            print(Fore.YELLOW + "[*] Securely deleting encrypted file...")
            FileHandler.secure_delete(file_path)
        
        print(Fore.GREEN + f"[+] File decrypted successfully: {output_path}")
        
    except Exception as e:
        print(Fore.RED + f"[!] Error during decryption: {e}")


def generate_password():
    """Generates a secure random password"""
    print(Fore.CYAN + "\nPassword Generator")
    
    # Get password length
    try:
        length = int(input(Fore.YELLOW + "[?] Password length (default: 16): ") or "16")
        if length < 4:
            print(Fore.RED + "[!] Password length must be at least 4 characters.")
            return
    except ValueError:
        print(Fore.RED + "[!] Please enter a valid number.")
        return
    
    # Get character set options
    use_uppercase = input(Fore.YELLOW + "[?] Include uppercase letters? (Y/n): ").lower() != 'n'
    use_lowercase = input(Fore.YELLOW + "[?] Include lowercase letters? (Y/n): ").lower() != 'n'
    use_digits = input(Fore.YELLOW + "[?] Include digits? (Y/n): ").lower() != 'n'
    use_symbols = input(Fore.YELLOW + "[?] Include symbols? (Y/n): ").lower() != 'n'
    
    # Ensure at least one character set is selected
    if not any([use_uppercase, use_lowercase, use_digits, use_symbols]):
        print(Fore.RED + "[!] At least one character set must be enabled.")
        return
    
    try:
        # Generate password
        password = PasswordGenerator.generate_password(
            length=length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_digits=use_digits,
            use_symbols=use_symbols
        )
        
        print(Fore.GREEN + f"\n[+] Generated password ({length} characters):")
        print(Fore.GREEN + f"{password}")
        
        # Try to copy to clipboard
        try:
            import pyperclip
            pyperclip.copy(password)
            print(Fore.GREEN + "[+] Password copied to clipboard!")
        except ImportError:
            print(Fore.YELLOW + "[*] Install 'pyperclip' package to enable clipboard functionality.")
        
    except Exception as e:
        print(Fore.RED + f"[!] Error generating password: {e}")


def shred_file():
    """Securely deletes a file selected by the user"""
    # List files
    files = list_files()
    if not files:
        return
    
    # Select file
    file_path = select_file(files)
    if not file_path:
        return
    
    # Get number of passes
    try:
        passes = int(input(Fore.YELLOW + "[?] Number of overwrite passes (default: 3): ") or "3")
        if passes < 1:
            print(Fore.RED + "[!] Number of passes must be at least 1.")
            return
    except ValueError:
        print(Fore.RED + "[!] Please enter a valid number.")
        return
    
    # Confirm deletion
    print(Fore.RED + f"\n[!] WARNING: File {file_path} will be permanently deleted and cannot be recovered!")
    response = input(Fore.RED + "[?] Are you absolutely sure? (type 'yes' to confirm): ")
    if response.lower() != 'yes':
        print(Fore.YELLOW + "[*] Operation cancelled.")
        return
    
    try:
        print(Fore.YELLOW + f"[*] Securely deleting file: {file_path}")
        print(Fore.YELLOW + f"[*] Using {passes} overwrite passes")
        
        FileHandler.secure_delete(file_path, passes=passes)
        
    except Exception as e:
        print(Fore.RED + f"[!] Error during secure deletion: {e}")


def show_recent_files():
    """Shows the list of recently accessed files"""
    config = ConfigManager.load_config()
    recent_files = config.get("recent_files", [])
    
    if not recent_files:
        print(Fore.YELLOW + "[*] No recent files found.")
        return
    
    print(Fore.CYAN + "\nRecent Files:")
    for idx, file_path in enumerate(recent_files):
        if os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            size_str = format_file_size(file_size)
            is_encrypted = file_path.endswith(FILE_EXTENSION)
            
            if is_encrypted:
                print(Fore.GREEN + f"  {idx + 1}. {file_path} ({size_str}) [ENCRYPTED]")
            else:
                print(Fore.CYAN + f"  {idx + 1}. {file_path} ({size_str})")
        else:
            print(Fore.RED + f"  {idx + 1}. {file_path} [FILE NOT FOUND]")
    
    # Option to clear recent files
    response = input(Fore.YELLOW + "\n[?] Clear recent files list? (y/n): ")
    if response.lower() == 'y':
        config["recent_files"] = []
        ConfigManager.save_config(config)
        print(Fore.GREEN + "[+] Recent files list cleared.")


def show_help():
    """Shows help information"""
    print(Fore.CYAN + "\nFlightCode CLI Help")
    print(Fore.CYAN + "=================")
    
    print(Fore.YELLOW + "\nAvailable Commands:")
    
    commands = [
        ("1", "Encrypt a file", "Encrypts a file with AES-256-GCM encryption"),
        ("2", "Decrypt a file", "Decrypts a previously encrypted file"),
        ("3", "Generate password", "Creates a secure random password"),
        ("4", "Shred a file", "Securely deletes a file beyond recovery"),
        ("5", "Recent files", "Shows recently accessed files"),
        ("6", "Help", "Shows this help information"),
        ("7", "About", "Shows information about FlightCode"),
        ("8", "Exit", "Exits the application")
    ]
    
    for cmd, name, desc in commands:
        print(Fore.GREEN + f"  {cmd}. {name}")
        print(Fore.CYAN + f"     {desc}")
    
    print(Fore.YELLOW + "\nSecurity Features:")
    features = [
        "• AES-256-GCM authenticated encryption",
        "• Argon2id key derivation (OWASP recommended)",
        "• Secure file deletion with multiple passes",
        "• Strong password generation"
    ]
    
    for feature in features:
        print(Fore.CYAN + f"  {feature}")
    
    print(Fore.YELLOW + "\nPress Enter to continue...")
    input()


def show_about():
    """Shows information about the application"""
    print(Fore.CYAN + "\nAbout FlightCode CLI")
    print(Fore.CYAN + "===================")
    
    print(Fore.YELLOW + f"\nVersion: {APP_VERSION}")
    print(Fore.YELLOW + "Author: Bell (github.com/Bell-O)")
    
    print(Fore.CYAN + "\nFlightCode is a secure file encryption tool that uses")
    print(Fore.CYAN + "AES-256-GCM encryption and Argon2id key derivation")
    print(Fore.CYAN + "to protect your sensitive files with end-to-end encryption.")
    
    print(Fore.YELLOW + "\nGitHub: https://github.com/Bell-O/FlightCode")
    
    print(Fore.YELLOW + "\nPress Enter to continue...")
    input()


def main():
    """Main entry point for the application"""
    # Check for command-line arguments
    if len(sys.argv) > 1:
        # Parse command-line arguments
        parser = argparse.ArgumentParser(
            description=f"{APP_NAME} v{APP_VERSION} - Secure File Encryption Tool",
            epilog="For more information, visit: https://github.com/Bell-O/FlightCode"
        )
        
        # Add version argument
        parser.add_argument('--version', action='version', version=f'{APP_NAME} v{APP_VERSION}')
        
        # Create subparsers for commands
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Encrypt command
        encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
        encrypt_parser.add_argument('file', help='File to encrypt')
        encrypt_parser.add_argument('-o', '--output', help='Output file path (default: input_file.hee)')
        encrypt_parser.add_argument('-s', '--secure-delete', action='store_true', help='Securely delete original file after encryption')
        encrypt_parser.add_argument('-p', '--passes', type=int, default=3, help='Number of passes for secure deletion (default: 3)')
        encrypt_parser.add_argument('-f', '--force', action='store_true', help='Overwrite output file if it exists')
        
        # Decrypt command
        decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
        decrypt_parser.add_argument('file', help='File to decrypt')
        decrypt_parser.add_argument('-o', '--output', help='Output file path (default: removes .hee extension)')
        decrypt_parser.add_argument('-s', '--secure-delete', action='store_true', help='Securely delete encrypted file after decryption')
        decrypt_parser.add_argument('-p', '--passes', type=int, default=3, help='Number of passes for secure deletion (default: 3)')
        decrypt_parser.add_argument('-f', '--force', action='store_true', help='Overwrite output file if it exists')
        
        # Password generator command
        genpass_parser = subparsers.add_parser('genpass', help='Generate a secure random password')
        genpass_parser.add_argument('-l', '--length', type=int, default=16, help='Password length (default: 16)')
        genpass_parser.add_argument('--no-uppercase', action='store_true', help='Exclude uppercase letters')
        genpass_parser.add_argument('--no-lowercase', action='store_true', help='Exclude lowercase letters')
        genpass_parser.add_argument('--no-digits', action='store_true', help='Exclude digits')
        genpass_parser.add_argument('--no-symbols', action='store_true', help='Exclude symbols')
        genpass_parser.add_argument('-c', '--copy', action='store_true', help='Copy password to clipboard')
        
        # Shred command
        shred_parser = subparsers.add_parser('shred', help='Securely delete a file')
        shred_parser.add_argument('file', help='File to securely delete')
        shred_parser.add_argument('-p', '--passes', type=int, default=3, help='Number of passes for secure deletion (default: 3)')
        shred_parser.add_argument('-f', '--force', action='store_true', help='Skip confirmation prompt')
        
        # Parse arguments
        args = parser.parse_args()
        
        # Execute command
        if args.command == 'encrypt':
            # Check if file exists
            if not os.path.exists(args.file):
                print(Fore.RED + f"[!] Error: File not found: {args.file}")
                return 1
                
            # Determine output path
            output_path = args.output if args.output else f"{args.file}{FILE_EXTENSION}"
            
            # Check if output file already exists
            if os.path.exists(output_path) and not args.force:
                response = input(Fore.YELLOW + f"[?] File {output_path} already exists. Overwrite? (y/n): ")
                if response.lower() != 'y':
                    print(Fore.YELLOW + "[*] Operation cancelled.")
                    return 1
            
            # Get password
            password = getpass.getpass(Fore.YELLOW + "[?] Enter password: ")
            confirm_password = getpass.getpass(Fore.YELLOW + "[?] Confirm password: ")
            
            if password != confirm_password:
                print(Fore.RED + "[!] Error: Passwords do not match.")
                return 1
            
            try:
                print(Fore.YELLOW + f"[*] Reading file: {args.file}")
                file_data = FileHandler.read_file(args.file)
                
                print(Fore.YELLOW + "[*] Encrypting data...")
                encrypted_data = CryptoService.encrypt_data(file_data, password)
                
                print(Fore.YELLOW + f"[*] Writing encrypted file: {output_path}")
                FileHandler.write_file(output_path, encrypted_data)
                
                # Add to recent files
                ConfigManager.add_recent_file(output_path)
                
                # Securely delete original if requested
                if args.secure_delete:
                    print(Fore.YELLOW + "[*] Securely deleting original file...")
                    FileHandler.secure_delete(args.file, passes=args.passes)
                
                print(Fore.GREEN + f"[+] Encryption completed successfully!")
                return 0
                
            except Exception as e:
                print(Fore.RED + f"[!] Error during encryption: {e}")
                return 1
                
        elif args.command == 'decrypt':
            # Check if file exists
            if not os.path.exists(args.file):
                print(Fore.RED + f"[!] Error: File not found: {args.file}")
                return 1
            
            # Determine output path
            if args.output:
                output_path = args.output
            else:
                if args.file.endswith(FILE_EXTENSION):
                    output_path = args.file[:-len(FILE_EXTENSION)]
                else:
                    output_path = f"{args.file}.decrypted"
            
            # Check if output file already exists
            if os.path.exists(output_path) and not args.force:
                response = input(Fore.YELLOW + f"[?] File {output_path} already exists. Overwrite? (y/n): ")
                if response.lower() != 'y':
                    print(Fore.YELLOW + "[*] Operation cancelled.")
                    return 1
            
            # Get password
            password = getpass.getpass(Fore.YELLOW + "[?] Enter password: ")
            
            try:
                print(Fore.YELLOW + f"[*] Reading encrypted file: {args.file}")
                encrypted_data = FileHandler.read_file(args.file)
                
                print(Fore.YELLOW + "[*] Decrypting data...")
                try:
                    decrypted_data = CryptoService.decrypt_data(encrypted_data, password)
                except InvalidTag:
                    print(Fore.RED + "[!] Error: Authentication failed. Invalid password or corrupted file.")
                    return 1
                
                print(Fore.YELLOW + f"[*] Writing decrypted file: {output_path}")
                FileHandler.write_file(output_path, decrypted_data)
                
                # Add to recent files
                ConfigManager.add_recent_file(output_path)
                
                # Securely delete encrypted file if requested
                if args.secure_delete:
                    print(Fore.YELLOW + "[*] Securely deleting encrypted file...")
                    FileHandler.secure_delete(args.file, passes=args.passes)
                
                print(Fore.GREEN + f"[+] Decryption completed successfully!")
                return 0
                
            except Exception as e:
                print(Fore.RED + f"[!] Error during decryption: {e}")
                return 1
                
        elif args.command == 'genpass':
            try:
                password = PasswordGenerator.generate_password(
                    length=args.length,
                    use_uppercase=not args.no_uppercase,
                    use_lowercase=not args.no_lowercase,
                    use_digits=not args.no_digits,
                    use_symbols=not args.no_symbols
                )
                
                print(Fore.GREEN + f"\n[+] Generated password ({args.length} characters):")
                print(Fore.GREEN + f"{password}")
                
                if args.copy:
                    try:
                        import pyperclip
                        pyperclip.copy(password)
                        print(Fore.GREEN + "[+] Password copied to clipboard!")
                    except ImportError:
                        print(Fore.YELLOW + "[*] Note: Install 'pyperclip' package to enable clipboard functionality.")
                
                return 0
                
            except Exception as e:
                print(Fore.RED + f"[!] Error generating password: {e}")
                return 1
                
        elif args.command == 'shred':
            # Check if file exists
            if not os.path.exists(args.file):
                print(Fore.RED + f"[!] Error: File not found: {args.file}")
                return 1
            
            # Confirm deletion
            if not args.force:
                print(Fore.RED + f"[!] WARNING: File {args.file} will be permanently deleted and cannot be recovered!")
                response = input(Fore.RED + "[?] Are you absolutely sure? (type 'yes' to confirm): ")
                if response.lower() != 'yes':
                    print(Fore.YELLOW + "[*] Operation cancelled.")
                    return 1
            
            try:
                print(Fore.YELLOW + f"[*] Securely deleting file: {args.file}")
                print(Fore.YELLOW + f"[*] Using {args.passes} overwrite passes")
                
                FileHandler.secure_delete(args.file, passes=args.passes)
                return 0
                
            except Exception as e:
                print(Fore.RED + f"[!] Error during secure deletion: {e}")
                return 1
        
        # Show help if no command specified
        else:
            parser.print_help()
            return 0
    
    # Interactive mode
    else:
        # Display banner
        display_banner()
        
        while True:
            print(Fore.MAGENTA + "\nMain Menu:")
            print(Fore.CYAN + "  1. Encrypt a file")
            print(Fore.CYAN + "  2. Decrypt a file")
            print(Fore.CYAN + "  3. Generate password")
            print(Fore.CYAN + "  4. Shred a file")
            print(Fore.CYAN + "  5. Recent files")
            print(Fore.CYAN + "  6. Help")
            print(Fore.CYAN + "  7. About")
            print(Fore.CYAN + "  8. Exit")
            
            choice = input(Fore.YELLOW + "\n[?] Select an option: ").strip()
            
            if choice == '1':
                encrypt_file()
            elif choice == '2':
                decrypt_file()
            elif choice == '3':
                generate_password()
            elif choice == '4':
                shred_file()
            elif choice == '5':
                show_recent_files()
            elif choice == '6':
                show_help()
            elif choice == '7':
                show_about()
            elif choice == '8':
                print(Fore.GREEN + "\n[+] Thank you for using FlightCode!")
                break
            else:
                print(Fore.RED + "\n[!] Invalid option. Please try again.")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[*] Operation cancelled by user.")
        sys.exit(1)