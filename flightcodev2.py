import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
from typing import Optional, Tuple, Dict, Any
import json
import base64
import hashlib
import time
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from PIL import Image, ImageTk, ImageDraw, ImageFont
import webbrowser

# Constants
APP_NAME = "FlightCode"
APP_VERSION = "2.0"
FILE_EXTENSION = ".hee"
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".flightcode_config.json")

# Professional Dark Theme Color Scheme
PRIMARY_BG = "#F0F0F0"  # Main background
SECONDARY_BG = "#FFFFFF"  # Secondary background
TERTIARY_BG = "#FFFFFF"  # Card background
ACCENT_COLOR = "#0078D7"  # Primary accent (blue)
ACCENT_HOVER = "#0063B1"  # Darker accent for hover
ACCENT_SECONDARY = "#00B7C3"  # Secondary accent (teal)
TEXT_PRIMARY = "#1A1A1A"  # Primary text (dark)
TEXT_SECONDARY = "#666666"  # Secondary text (gray)
TEXT_DISABLED = "#999999"  # Disabled text
BORDER_COLOR = "#E0E0E0"  # Border color
SUCCESS_COLOR = "#00CA4E"  # Success color
WARNING_COLOR = "#FFBD44"  # Warning color
ERROR_COLOR = "#FF605C"  # Error color
GRID_COLOR = "#F5F5F5"  # Grid lines

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
            for _ in range(passes):
                # Seek to beginning of file
                f.seek(0)
                
                # Write random data
                f.write(os.urandom(file_size))
                
                # Flush to disk
                f.flush()
                os.fsync(f.fileno())
        
        # Finally delete the file
        os.remove(file_path)


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
            "theme": "dark",
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
            print(f"Error saving configuration: {e}")
    
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


class ProfessionalUI(tk.Tk):
    """Professional UI for the FlightCode application"""
    
    def __init__(self):
        super().__init__()
        
        # Load configuration
        self.app_config = ConfigManager.load_config()
        
        # Set up the window
        self.title(f"{APP_NAME} {APP_VERSION}")
        self.geometry("1000x700")
        self.minsize(900, 600)
        self.configure(bg=PRIMARY_BG)
        
        # Variables
        self.file_path = None
        self.password_var = tk.StringVar()
        self.confirm_password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar(value=False)
        self.secure_delete_var = tk.BooleanVar(value=self.app_config.get("secure_delete", True))
        self.active_tab = tk.StringVar(value="encrypt")
        
        # Create custom styles
        self.create_styles()
        
        # Create UI
        self.create_sidebar()
        self.create_main_content()
        
        # Center window
        self.center_window()
        
        # Bind events
        self.bind("<Escape>", lambda e: self.focus())
    
    def create_styles(self):
        """Create custom ttk styles"""
        style = ttk.Style()
        
        # Configure base styles
        style.configure('TFrame', background=PRIMARY_BG)
        style.configure('TLabel', background=PRIMARY_BG, foreground=TEXT_PRIMARY, font=('Segoe UI', 10))
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('TEntry', font=('Segoe UI', 10))
        style.configure('TCheckbutton', background=PRIMARY_BG, foreground=TEXT_PRIMARY, font=('Segoe UI', 10))
        
        # Custom styles
        style.configure('Sidebar.TFrame', background=SECONDARY_BG)
        style.configure('Content.TFrame', background=PRIMARY_BG)
        style.configure('Card.TFrame', background=TERTIARY_BG)
        
        # Labels
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), foreground=ACCENT_COLOR, background=SECONDARY_BG)
        style.configure('Heading.TLabel', font=('Segoe UI', 14, 'bold'), foreground=TEXT_PRIMARY, background=PRIMARY_BG)
        style.configure('SubHeading.TLabel', font=('Segoe UI', 12), foreground=TEXT_SECONDARY, background=PRIMARY_BG)
        style.configure('Card.TLabel', background=TERTIARY_BG, foreground=TEXT_PRIMARY)
        style.configure('Status.TLabel', font=('Segoe UI', 9), foreground=TEXT_SECONDARY, background=TERTIARY_BG)
        
        # Buttons
        style.configure('Primary.TButton', background=ACCENT_COLOR, foreground=TEXT_PRIMARY)
        style.map('Primary.TButton',
            background=[('active', ACCENT_HOVER), ('pressed', ACCENT_HOVER)],
            foreground=[('active', TEXT_PRIMARY), ('pressed', TEXT_PRIMARY)]
        )
        
        style.configure('Secondary.TButton', background=TERTIARY_BG, foreground=TEXT_PRIMARY)
        style.map('Secondary.TButton',
            background=[('active', SECONDARY_BG), ('pressed', SECONDARY_BG)],
            foreground=[('active', TEXT_PRIMARY), ('pressed', TEXT_PRIMARY)]
        )
        
        style.configure('Menu.TButton', background=SECONDARY_BG, foreground=TEXT_SECONDARY, borderwidth=0)
        style.map('Menu.TButton',
            background=[('active', PRIMARY_BG), ('pressed', PRIMARY_BG)],
            foreground=[('active', TEXT_PRIMARY), ('pressed', TEXT_PRIMARY)]
        )
        
        style.configure('ActiveMenu.TButton', background=PRIMARY_BG, foreground=TEXT_PRIMARY, borderwidth=0)
        
        # Progress bar
        style.configure('TProgressbar', background=ACCENT_COLOR, troughcolor=SECONDARY_BG)
        
        # Entry
        style.configure('TEntry', fieldbackground=SECONDARY_BG, foreground=TEXT_PRIMARY, insertcolor=TEXT_PRIMARY)
        
        # Checkbutton
        style.map('TCheckbutton',
            background=[('active', PRIMARY_BG)],
            foreground=[('active', TEXT_PRIMARY)]
        )
        
        # Separator
        style.configure('TSeparator', background=BORDER_COLOR)
    
    def center_window(self):
        """Centers the window on the screen"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_sidebar(self):
        """Creates the application sidebar"""
        sidebar_frame = ttk.Frame(self, style='Sidebar.TFrame', width=200)
        sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        sidebar_frame.pack_propagate(False)  # Prevent frame from shrinking
        
        # App title
        title_frame = ttk.Frame(sidebar_frame, style='Sidebar.TFrame')
        title_frame.pack(fill=tk.X, padx=0, pady=(20, 30))
        
        title_label = ttk.Label(
            title_frame, 
            text=APP_NAME, 
            style='Title.TLabel'
        )
        title_label.pack(anchor=tk.CENTER)
        
        version_label = ttk.Label(
            title_frame,
            text=f"v{APP_VERSION}",
            style='SubHeading.TLabel',
            font=('Segoe UI', 9),
            foreground=TEXT_SECONDARY,
            background=SECONDARY_BG
        )
        version_label.pack(anchor=tk.CENTER)
        
        # Navigation menu
        menu_items = [
            ("Encrypt", "encrypt", "🔒"),
            ("Decrypt", "decrypt", "🔓"),
            ("Password Generator", "password_gen", "🔑"),
            ("File Shredder", "shredder", "🗑️"),
            ("Settings", "settings", "⚙️"),
            ("About", "about", "ℹ️")
        ]
        
        for text, value, icon in menu_items:
            button_style = 'ActiveMenu.TButton' if value == self.active_tab.get() else 'Menu.TButton'
            button = ttk.Button(
                sidebar_frame,
                text=f"{icon}  {text}",
                command=lambda v=value: self.change_tab(v),
                style=button_style,
                width=25
            )
            button.pack(fill=tk.X, padx=0, pady=5)
        
        # Status indicator at bottom
        status_frame = ttk.Frame(sidebar_frame, style='Sidebar.TFrame')
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)
        
        status_label = ttk.Label(
            status_frame,
            text="Ready",
            style='SubHeading.TLabel',
            foreground=SUCCESS_COLOR,
            background=SECONDARY_BG,
            font=('Segoe UI', 9)
        )
        status_label.pack(side=tk.LEFT)
    
    def change_tab(self, tab_value):
        """Changes the active tab"""
        self.active_tab.set(tab_value)
        
        # Recreate the UI with the new tab
        for widget in self.winfo_children():
            widget.destroy()
        
        self.create_styles()
        self.create_sidebar()
        self.create_main_content()
    
    def create_main_content(self):
        """Creates the main content area based on active tab"""
        main_frame = ttk.Frame(self, style='Content.TFrame')
        main_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Header with breadcrumbs
        header_frame = ttk.Frame(main_frame, style='Content.TFrame')
        header_frame.pack(fill=tk.X, padx=30, pady=(30, 20))
        
        # Breadcrumbs
        tab = self.active_tab.get()
        breadcrumb_text = f"Home > {tab.replace('_', ' ').title()}"
        breadcrumb_label = ttk.Label(
            header_frame,
            text=breadcrumb_text,
            style='SubHeading.TLabel',
            font=('Segoe UI', 10)
        )
        breadcrumb_label.pack(anchor=tk.W)
        
        # Page title
        title_text = self.get_page_title(tab)
        page_title = ttk.Label(
            header_frame,
            text=title_text,
            style='Heading.TLabel',
            font=('Segoe UI', 20, 'bold')
        )
        page_title.pack(anchor=tk.W, pady=(5, 0))
        
        # Content based on active tab
        if tab == "encrypt":
            self.create_encrypt_content(main_frame)
        elif tab == "decrypt":
            self.create_decrypt_content(main_frame)
        elif tab == "password_gen":
            self.create_password_generator_content(main_frame)
        elif tab == "shredder":
            self.create_file_shredder_content(main_frame)
        elif tab == "settings":
            self.create_settings_content(main_frame)
        elif tab == "about":
            self.create_about_content(main_frame)
    
    def get_page_title(self, tab):
        """Returns the title for the current page"""
        titles = {
            "encrypt": "Encrypt Files",
            "decrypt": "Decrypt Files",
            "password_gen": "Password Generator",
            "shredder": "File Shredder",
            "settings": "Settings",
            "about": "About"
        }
        return titles.get(tab, "")
    
    def create_encrypt_content(self, parent):
        """Creates the encryption tab content"""
        # Main content container
        content_frame = ttk.Frame(parent, style='Content.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Two-column layout
        columns_frame = ttk.Frame(content_frame, style='Content.TFrame')
        columns_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column - File selection
        left_column = ttk.Frame(columns_frame, style='Content.TFrame')
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        file_card = ttk.Frame(left_column, style='Card.TFrame')
        file_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        card_header = ttk.Frame(file_card, style='Card.TFrame')
        card_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        file_title = ttk.Label(
            card_header,
            text="Select File",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        file_title.pack(anchor=tk.W)
        
        # Card content
        card_content = ttk.Frame(file_card, style='Card.TFrame')
        card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # File selection
        file_frame = ttk.Frame(card_content, style='Card.TFrame')
        file_frame.pack(fill=tk.X, pady=10)
        
        self.file_entry = ttk.Entry(file_frame, style='TEntry')
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_button = ttk.Button(
            file_frame,
            text="Browse",
            command=self.select_file,
            style='Secondary.TButton'
        )
        browse_button.pack(side=tk.RIGHT)
        
        # File info
        self.file_info_var = tk.StringVar()
        file_info_label = ttk.Label(
            card_content,
            textvariable=self.file_info_var,
            style='Status.TLabel'
        )
        file_info_label.pack(anchor=tk.W, pady=10)
        
        # Divider - Use ttk.Separator instead of a custom frame
        ttk.Separator(card_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Options section
        options_title = ttk.Label(
            card_content,
            text="Options",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        options_title.pack(anchor=tk.W, pady=(0, 10))
        
        secure_delete_check = ttk.Checkbutton(
            card_content,
            text="Securely delete original file after encryption",
            variable=self.secure_delete_var,
            style='TCheckbutton'
        )
        secure_delete_check.pack(anchor=tk.W, pady=5)
        
        # Recent files section
        recent_title = ttk.Label(
            card_content,
            text="Recent Files",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        recent_title.pack(anchor=tk.W, pady=(20, 10))
        
        # Recent files list
        recent_files = self.app_config.get("recent_files", [])[:5]
        
        if recent_files:
            for file_path in recent_files:
                file_name = os.path.basename(file_path)
                recent_file_button = ttk.Button(
                    card_content,
                    text=file_name,
                    command=lambda p=file_path: self.load_recent_file(p),
                    style='Secondary.TButton'
                )
                recent_file_button.pack(anchor=tk.W, pady=5, fill=tk.X)
        else:
            no_recent_label = ttk.Label(
                card_content,
                text="No recent files",
                style='Status.TLabel'
            )
            no_recent_label.pack(anchor=tk.W, pady=5)
        
        # Right column - Password
        right_column = ttk.Frame(columns_frame, style='Content.TFrame')
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(15, 0))
        
        password_card = ttk.Frame(right_column, style='Card.TFrame')
        password_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        password_header = ttk.Frame(password_card, style='Card.TFrame')
        password_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        password_title = ttk.Label(
            password_header,
            text="Set Password",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        password_title.pack(anchor=tk.W)
        
        # Card content
        password_content = ttk.Frame(password_card, style='Card.TFrame')
        password_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Password entry
        password_label = ttk.Label(
            password_content,
            text="Password:",
            style='Card.TLabel'
        )
        password_label.pack(anchor=tk.W, pady=(10, 5))
        
        self.password_entry = ttk.Entry(
            password_content,
            textvariable=self.password_var,
            show="•",
            style='TEntry'
        )
        self.password_entry.pack(fill=tk.X, pady=5)
        
        # Password strength meter
        self.strength_frame = ttk.Frame(password_content, style='Card.TFrame')
        self.strength_frame.pack(fill=tk.X, pady=5)
        
        self.strength_var = tk.DoubleVar(value=0)
        self.strength_bar = ttk.Progressbar(
            self.strength_frame,
            variable=self.strength_var,
            mode="determinate",
            length=100,
            style='TProgressbar'
        )
        self.strength_bar.pack(fill=tk.X)
        
        self.strength_text_var = tk.StringVar()
        self.strength_label = ttk.Label(
            self.strength_frame,
            textvariable=self.strength_text_var,
            style='Status.TLabel'
        )
        self.strength_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Bind password change event
        self.password_var.trace_add("write", self.check_password_strength)
        
        # Confirm password
        confirm_label = ttk.Label(
            password_content,
            text="Confirm Password:",
            style='Card.TLabel'
        )
        confirm_label.pack(anchor=tk.W, pady=(15, 5))
        
        self.confirm_entry = ttk.Entry(
            password_content,
            textvariable=self.confirm_password_var,
            show="•",
            style='TEntry'
        )
        self.confirm_entry.pack(fill=tk.X, pady=5)
        
        # Password match indicator
        self.match_var = tk.StringVar()
        match_label = ttk.Label(
            password_content,
            textvariable=self.match_var,
            style='Card.TLabel'
        )
        match_label.pack(anchor=tk.W, pady=5)
        
        # Bind confirm password change event
        self.confirm_password_var.trace_add("write", self.check_passwords_match)
        
        # Show password checkbox
        show_password_check = ttk.Checkbutton(
            password_content,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            style='TCheckbutton'
        )
        show_password_check.pack(anchor=tk.W, pady=10)
        
        # Divider - Use ttk.Separator
        ttk.Separator(password_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Encrypt button
        encrypt_button = ttk.Button(
            password_content,
            text="ENCRYPT FILE",
            command=self.encrypt_file,
            style='Primary.TButton'
        )
        encrypt_button.pack(fill=tk.X, pady=(10, 15))
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            password_content,
            variable=self.progress_var,
            mode="determinate",
            style='TProgressbar'
        )
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Progress text
        self.progress_text_var = tk.StringVar()
        progress_label = ttk.Label(
            password_content,
            textvariable=self.progress_text_var,
            style='Status.TLabel'
        )
        progress_label.pack(anchor=tk.W, pady=(5, 15))
    
    def create_decrypt_content(self, parent):
        """Creates the decryption tab content"""
        # Main content container
        content_frame = ttk.Frame(parent, style='Content.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Two-column layout
        columns_frame = ttk.Frame(content_frame, style='Content.TFrame')
        columns_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column - File selection
        left_column = ttk.Frame(columns_frame, style='Content.TFrame')
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        file_card = ttk.Frame(left_column, style='Card.TFrame')
        file_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        card_header = ttk.Frame(file_card, style='Card.TFrame')
        card_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        file_title = ttk.Label(
            card_header,
            text="Select Encrypted File",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        file_title.pack(anchor=tk.W)
        
        # Card content
        card_content = ttk.Frame(file_card, style='Card.TFrame')
        card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # File selection
        file_frame = ttk.Frame(card_content, style='Card.TFrame')
        file_frame.pack(fill=tk.X, pady=10)
        
        self.decrypt_file_entry = ttk.Entry(file_frame, style='TEntry')
        self.decrypt_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_button = ttk.Button(
            file_frame,
            text="Browse",
            command=lambda: self.select_file(encrypted=True),
            style='Secondary.TButton'
        )
        browse_button.pack(side=tk.RIGHT)
        
        # File info
        self.decrypt_file_info_var = tk.StringVar()
        file_info_label = ttk.Label(
            card_content,
            textvariable=self.decrypt_file_info_var,
            style='Status.TLabel'
        )
        file_info_label.pack(anchor=tk.W, pady=10)
        
        # Divider - Use ttk.Separator
        ttk.Separator(card_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Options section
        options_title = ttk.Label(
            card_content,
            text="Options",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        options_title.pack(anchor=tk.W, pady=(0, 10))
        
        secure_delete_decrypt_var = tk.BooleanVar(value=self.app_config.get("secure_delete", True))
        secure_delete_check = ttk.Checkbutton(
            card_content,
            text="Securely delete encrypted file after decryption",
            variable=secure_delete_decrypt_var,
            style='TCheckbutton'
        )
        secure_delete_check.pack(anchor=tk.W, pady=5)
        
        # Recent files section
        recent_title = ttk.Label(
            card_content,
            text="Recent Files",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        recent_title.pack(anchor=tk.W, pady=(20, 10))
        
        # Recent files list
        recent_files = [f for f in self.app_config.get("recent_files", [])[:5] if f.endswith(FILE_EXTENSION)]
        
        if recent_files:
            for file_path in recent_files:
                file_name = os.path.basename(file_path)
                recent_file_button = ttk.Button(
                    card_content,
                    text=file_name,
                    command=lambda p=file_path: self.load_recent_file(p, encrypted=True),
                    style='Secondary.TButton'
                )
                recent_file_button.pack(anchor=tk.W, pady=5, fill=tk.X)
        else:
            no_recent_label = ttk.Label(
                card_content,
                text="No recent encrypted files",
                style='Status.TLabel'
            )
            no_recent_label.pack(anchor=tk.W, pady=5)
        
        # Right column - Password
        right_column = ttk.Frame(columns_frame, style='Content.TFrame')
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(15, 0))
        
        password_card = ttk.Frame(right_column, style='Card.TFrame')
        password_card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        password_header = ttk.Frame(password_card, style='Card.TFrame')
        password_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        password_title = ttk.Label(
            password_header,
            text="Enter Password",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        password_title.pack(anchor=tk.W)
        
        # Card content
        password_content = ttk.Frame(password_card, style='Card.TFrame')
        password_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Password entry
        password_label = ttk.Label(
            password_content,
            text="Password:",
            style='Card.TLabel'
        )
        password_label.pack(anchor=tk.W, pady=(10, 5))
        
        self.decrypt_password_entry = ttk.Entry(
            password_content,
            show="•",
            style='TEntry'
        )
        self.decrypt_password_entry.pack(fill=tk.X, pady=5)
        
        # Show password checkbox
        show_decrypt_password_var = tk.BooleanVar(value=False)
        show_password_check = ttk.Checkbutton(
            password_content,
            text="Show Password",
            variable=show_decrypt_password_var,
            command=lambda: self.toggle_decrypt_password_visibility(show_decrypt_password_var),
            style='TCheckbutton'
        )
        show_password_check.pack(anchor=tk.W, pady=10)
        
        # Divider - Use ttk.Separator
        ttk.Separator(password_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Decrypt button
        decrypt_button = ttk.Button(
            password_content,
            text="DECRYPT FILE",
            command=lambda: self.decrypt_file(secure_delete_decrypt_var.get()),
            style='Primary.TButton'
        )
        decrypt_button.pack(fill=tk.X, pady=(10, 15))
        
        # Progress bar
        self.decrypt_progress_var = tk.DoubleVar()
        self.decrypt_progress_bar = ttk.Progressbar(
            password_content,
            variable=self.decrypt_progress_var,
            mode="determinate",
            style='TProgressbar'
        )
        self.decrypt_progress_bar.pack(fill=tk.X, pady=5)
        
        # Progress text
        self.decrypt_progress_text_var = tk.StringVar()
        progress_label = ttk.Label(
            password_content,
            textvariable=self.decrypt_progress_text_var,
            style='Status.TLabel'
        )
        progress_label.pack(anchor=tk.W, pady=(5, 15))
    
    def create_password_generator_content(self, parent):
        """Creates the password generator tab content"""
        # Main content container
        content_frame = ttk.Frame(parent, style='Content.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Card
        card = ttk.Frame(content_frame, style='Card.TFrame')
        card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        card_header = ttk.Frame(card, style='Card.TFrame')
        card_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        header_label = ttk.Label(
            card_header,
            text="Generate Secure Passwords",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        header_label.pack(anchor=tk.W)
        
        # Card content
        card_content = ttk.Frame(card, style='Card.TFrame')
        card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Options section
        options_frame = ttk.Frame(card_content, style='Card.TFrame')
        options_frame.pack(fill=tk.X, pady=10)
        
        # Length option
        length_frame = ttk.Frame(options_frame, style='Card.TFrame')
        length_frame.pack(fill=tk.X, pady=10)
        
        length_label = ttk.Label(
            length_frame, 
            text="Password Length:",
            style='Card.TLabel'
        )
        length_label.pack(side=tk.LEFT)
        
        length_var = tk.IntVar(value=16)
        length_spinbox = ttk.Spinbox(
            length_frame, 
            from_=8, 
            to=64, 
            textvariable=length_var,
            width=5
        )
        length_spinbox.pack(side=tk.RIGHT)
        
        # Character options
        char_frame = ttk.Frame(options_frame, style='Card.TFrame')
        char_frame.pack(fill=tk.X, pady=10)
        
        uppercase_var = tk.BooleanVar(value=True)
        uppercase_check = ttk.Checkbutton(
            char_frame, 
            text="Include Uppercase Letters (A-Z)", 
            variable=uppercase_var,
            style='TCheckbutton'
        )
        uppercase_check.pack(anchor=tk.W, pady=2)
        
        lowercase_var = tk.BooleanVar(value=True)
        lowercase_check = ttk.Checkbutton(
            char_frame, 
            text="Include Lowercase Letters (a-z)", 
            variable=lowercase_var,
            style='TCheckbutton'
        )
        lowercase_check.pack(anchor=tk.W, pady=2)
        
        digits_var = tk.BooleanVar(value=True)
        digits_check = ttk.Checkbutton(
            char_frame, 
            text="Include Digits (0-9)", 
            variable=digits_var,
            style='TCheckbutton'
        )
        digits_check.pack(anchor=tk.W, pady=2)
        
        symbols_var = tk.BooleanVar(value=True)
        symbols_check = ttk.Checkbutton(
            char_frame, 
            text="Include Symbols (!@#$%^&*)", 
            variable=symbols_var,
            style='TCheckbutton'
        )
        symbols_check.pack(anchor=tk.W, pady=2)
        
        # Divider - Use ttk.Separator
        ttk.Separator(card_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Generated password
        password_frame = ttk.Frame(card_content, style='Card.TFrame')
        password_frame.pack(fill=tk.X, pady=10)
        
        password_label = ttk.Label(
            password_frame,
            text="Generated Password:",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        password_label.pack(anchor=tk.W, pady=(0, 10))
        
        password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_frame, 
            textvariable=password_var,
            font=("Consolas", 12),
            style='TEntry'
        )
        password_entry.pack(fill=tk.X, pady=5)
        
        # Buttons
        def generate_password():
            """Generates a random password based on selected options"""
            import random
            import string
            
            # Get character sets
            chars = ""
            if uppercase_var.get():
                chars += string.ascii_uppercase
            if lowercase_var.get():
                chars += string.ascii_lowercase
            if digits_var.get():
                chars += string.digits
            if symbols_var.get():
                chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
            
            # Ensure at least one character set is selected
            if not chars:
                messagebox.showerror(
                    "Error", 
                    "Please select at least one character set."
                )
                return
            
            # Generate password
            length = length_var.get()
            password = "".join(random.choice(chars) for _ in range(length))
            password_var.set(password)
            
            # Select password for easy copying
            password_entry.select_range(0, tk.END)
            password_entry.focus_set()
        
        def copy_to_clipboard():
            """Copies the generated password to clipboard"""
            password = password_var.get()
            if password:
                self.clipboard_clear()
                self.clipboard_append(password)
                messagebox.showinfo("Copied", "Password copied to clipboard")
        
        button_frame = ttk.Frame(card_content, style='Card.TFrame')
        button_frame.pack(fill=tk.X, pady=15)
        
        generate_button = ttk.Button(
            button_frame, 
            text="GENERATE PASSWORD", 
            command=generate_password,
            style='Primary.TButton'
        )
        generate_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        copy_button = ttk.Button(
            button_frame, 
            text="COPY TO CLIPBOARD", 
            command=copy_to_clipboard,
            style='Secondary.TButton'
        )
        copy_button.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(5, 0))
        
        # Generate initial password
        generate_password()
    
    def create_file_shredder_content(self, parent):
        """Creates the file shredder tab content"""
        # Main content container
        content_frame = ttk.Frame(parent, style='Content.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Card
        card = ttk.Frame(content_frame, style='Card.TFrame')
        card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        card_header = ttk.Frame(card, style='Card.TFrame')
        card_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        header_label = ttk.Label(
            card_header,
            text="Securely Delete Files",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        header_label.pack(anchor=tk.W)
        
        # Card content
        card_content = ttk.Frame(card, style='Card.TFrame')
        card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Warning
        warning_frame = ttk.Frame(card_content, style='Card.TFrame')
        warning_frame.pack(fill=tk.X, pady=10)
        
        warning_label = ttk.Label(
            warning_frame, 
            text="WARNING: Files will be permanently deleted and cannot be recovered!",
            foreground=ERROR_COLOR,
            font=("Segoe UI", 10, "bold"),
            style='Card.TLabel'
        )
        warning_label.pack(pady=10)
        
        # File selection
        file_frame = ttk.Frame(card_content, style='Card.TFrame')
        file_frame.pack(fill=tk.X, pady=10)
        
        file_label = ttk.Label(
            file_frame,
            text="Select File to Shred:",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        file_label.pack(anchor=tk.W, pady=(0, 10))
        
        file_select_frame = ttk.Frame(file_frame, style='Card.TFrame')
        file_select_frame.pack(fill=tk.X)
        
        file_var = tk.StringVar()
        file_entry = ttk.Entry(file_select_frame, textvariable=file_var, style='TEntry')
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        def select_shred_file():
            """Opens a file dialog to select a file to shred"""
            file_path = filedialog.askopenfilename(
                initialdir=self.app_config.get("last_directory", os.path.expanduser("~")),
                title="Select File to Shred",
                filetypes=[("All Files", "*.*")]
            )
            if file_path:
                file_var.set(file_path)
        
        browse_button = ttk.Button(
            file_select_frame, 
            text="Browse", 
            command=select_shred_file,
            style='Secondary.TButton'
        )
        browse_button.pack(side=tk.RIGHT)
        
        # Divider - Use ttk.Separator
        ttk.Separator(card_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Options
        options_frame = ttk.Frame(card_content, style='Card.TFrame')
        options_frame.pack(fill=tk.X, pady=10)
        
        options_label = ttk.Label(
            options_frame,
            text="Shredding Options:",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        options_label.pack(anchor=tk.W, pady=(0, 10))
        
        passes_frame = ttk.Frame(options_frame, style='Card.TFrame')
        passes_frame.pack(fill=tk.X, pady=5)
        
        passes_label = ttk.Label(
            passes_frame, 
            text="Number of Passes:",
            style='Card.TLabel'
        )
        passes_label.pack(side=tk.LEFT)
        
        passes_var = tk.IntVar(value=3)
        passes_spinbox = ttk.Spinbox(
            passes_frame, 
            from_=1, 
            to=10, 
            textvariable=passes_var,
            width=5
        )
        passes_spinbox.pack(side=tk.RIGHT)
        
        # Progress
        progress_frame = ttk.Frame(card_content, style='Card.TFrame')
        progress_frame.pack(fill=tk.X, pady=15)
        
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=progress_var,
            mode="determinate",
            style='TProgressbar'
        )
        progress_bar.pack(fill=tk.X, pady=5)
        
        progress_label_var = tk.StringVar()
        progress_label = ttk.Label(
            progress_frame, 
            textvariable=progress_label_var,
            style='Status.TLabel'
        )
        progress_label.pack(anchor=tk.W, pady=5)
        
        # Shred button
        def shred_file():
            """Shreds the selected file"""
            file_path = file_var.get()
            if not file_path or not os.path.exists(file_path):
                messagebox.showerror("Error", "Please select a valid file to shred.")
                return
            
            # Confirm shredding
            result = messagebox.askyesno(
                "Confirm Shredding", 
                f"Are you sure you want to permanently delete {os.path.basename(file_path)}?\n\n"
                "This action CANNOT be undone!"
            )
            if not result:
                return
            
            # Start shredding in a separate thread
            threading.Thread(
                target=_shred_file_thread,
                args=(file_path, passes_var.get()),
                daemon=True
            ).start()
        
        def _shred_file_thread(file_path, passes):
            """Thread function for file shredding"""
            try:
                # Update UI
                progress_var.set(0)
                progress_label_var.set("Preparing to shred file...")
                shred_button.config(state=tk.DISABLED)
                
                # Get file size for progress updates
                file_size = os.path.getsize(file_path)
                
                # Update progress for each pass
                for i in range(passes):
                    progress_var.set((i / passes) * 100)
                    progress_label_var.set(f"Pass {i+1}/{passes}: Overwriting with random data...")
                    time.sleep(0.5)  # Simulate work
                
                # Shred file
                FileHandler.secure_delete(file_path, passes=passes)
                
                # Update UI
                progress_var.set(100)
                progress_label_var.set("File successfully shredded!")
                
                # Show success message
                messagebox.showinfo(
                    "Success", 
                    f"File {os.path.basename(file_path)} has been permanently deleted."
                )
                
                # Clear file entry
                file_var.set("")
                shred_button.config(state=tk.NORMAL)
                
            except Exception as e:
                # Handle errors
                progress_label_var.set("Shredding failed!")
                messagebox.showerror("Error", f"Error during file shredding:\n{e}")
                shred_button.config(state=tk.NORMAL)
        
        button_frame = ttk.Frame(card_content, style='Card.TFrame')
        button_frame.pack(fill=tk.X, pady=15)
        
        shred_button = ttk.Button(
            button_frame, 
            text="SHRED FILE", 
            command=shred_file,
            style='Primary.TButton'
        )
        shred_button.pack(fill=tk.X)
    
    def create_settings_content(self, parent):
        """Creates the settings tab content"""
        # Main content container
        content_frame = ttk.Frame(parent, style='Content.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Card
        card = ttk.Frame(content_frame, style='Card.TFrame')
        card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card header
        card_header = ttk.Frame(card, style='Card.TFrame')
        card_header.pack(fill=tk.X, padx=20, pady=(20, 10))
        
        header_label = ttk.Label(
            card_header,
            text="Application Settings",
            style='Card.TLabel',
            font=('Segoe UI', 14, 'bold')
        )
        header_label.pack(anchor=tk.W)
        
        # Card content
        card_content = ttk.Frame(card, style='Card.TFrame')
        card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Secure deletion settings
        secure_frame = ttk.Frame(card_content, style='Card.TFrame')
        secure_frame.pack(fill=tk.X, pady=10)
        
        secure_label = ttk.Label(
            secure_frame,
            text="Secure Deletion:",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        secure_label.pack(anchor=tk.W, pady=(0, 10))
        
        secure_delete_var = tk.BooleanVar(value=self.app_config.get("secure_delete", True))
        secure_delete_check = ttk.Checkbutton(
            secure_frame, 
            text="Enable secure deletion by default", 
            variable=secure_delete_var,
            style='TCheckbutton'
        )
        secure_delete_check.pack(anchor=tk.W, pady=5)
        
        passes_frame = ttk.Frame(secure_frame, style='Card.TFrame')
        passes_frame.pack(fill=tk.X, pady=5)
        
        passes_label = ttk.Label(
            passes_frame, 
            text="Number of overwrite passes:",
            style='Card.TLabel'
        )
        passes_label.pack(side=tk.LEFT)
        
        passes_var = tk.IntVar(value=self.app_config.get("secure_delete_passes", 3))
        passes_spinbox = ttk.Spinbox(
            passes_frame, 
            from_=1, 
            to=10, 
            textvariable=passes_var,
            width=5
        )
        passes_spinbox.pack(side=tk.RIGHT)
        
        # Divider - Use ttk.Separator
        ttk.Separator(card_content, orient='horizontal').pack(fill=tk.X, pady=15)
        
        # Clear recent files
        recent_frame = ttk.Frame(card_content, style='Card.TFrame')
        recent_frame.pack(fill=tk.X, pady=10)
        
        recent_label = ttk.Label(
            recent_frame,
            text="Recent Files:",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        recent_label.pack(anchor=tk.W, pady=(0, 10))
        
        def clear_recent_files():
            """Clears the recent files list"""
            self.app_config["recent_files"] = []
            ConfigManager.save_config(self.app_config)
            messagebox.showinfo("Success", "Recent files list has been cleared.")
        
        clear_button = ttk.Button(
            recent_frame,
            text="Clear Recent Files List",
            command=clear_recent_files,
            style='Secondary.TButton'
        )
        clear_button.pack(anchor=tk.W, pady=5)
        
        # Save settings
        def save_settings():
            self.app_config["secure_delete"] = secure_delete_var.get()
            self.app_config["secure_delete_passes"] = passes_var.get()
            ConfigManager.save_config(self.app_config)
            messagebox.showinfo("Success", "Settings saved successfully.")
        
        # Buttons
        button_frame = ttk.Frame(card_content, style='Card.TFrame')
        button_frame.pack(fill=tk.X, pady=20)
        
        save_button = ttk.Button(
            button_frame,
            text="SAVE SETTINGS",
            command=save_settings,
            style='Primary.TButton'
        )
        save_button.pack(fill=tk.X)
    
    def create_about_content(self, parent):
        """Creates the about tab content"""
        # Main content container
        content_frame = ttk.Frame(parent, style='Content.TFrame')
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Card
        card = ttk.Frame(content_frame, style='Card.TFrame')
        card.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Card content
        card_content = ttk.Frame(card, style='Card.TFrame')
        card_content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # App info
        app_title = ttk.Label(
            card_content,
            text=APP_NAME,
            style='Card.TLabel',
            font=('Segoe UI', 24, 'bold'),
            foreground=ACCENT_COLOR
        )
        app_title.pack(anchor=tk.CENTER, pady=(40, 5))
        
        version_label = ttk.Label(
            card_content,
            text=f"Version {APP_VERSION}",
            style='Card.TLabel',
            font=('Segoe UI', 12)
        )
        version_label.pack(anchor=tk.CENTER, pady=5)
        
        # Description
        description = (
            "FlightCode is a secure file encryption tool that uses\n"
            "AES-256-GCM encryption and Argon2id key derivation\n"
            "to protect your sensitive files with end-to-end encryption."
        )
        
        desc_label = ttk.Label(
            card_content,
            text=description,
            style='Card.TLabel',
            justify=tk.CENTER,
            font=('Segoe UI', 11)
        )
        desc_label.pack(anchor=tk.CENTER, pady=30)
        
        # Security info
        security_frame = ttk.Frame(card_content, style='Card.TFrame')
        security_frame.pack(fill=tk.X, pady=10)
        
        security_title = ttk.Label(
            security_frame,
            text="Security Features:",
            style='Card.TLabel',
            font=('Segoe UI', 12, 'bold')
        )
        security_title.pack(anchor=tk.CENTER, pady=5)
        
        features = [
            "• AES-256-GCM authenticated encryption",
            "• Argon2id key derivation (OWASP recommended)",
            "• Secure file deletion with multiple passes",
            "• Strong password generation"
        ]
        
        for feature in features:
            feature_label = ttk.Label(
                security_frame,
                text=feature,
                style='Card.TLabel'
            )
            feature_label.pack(anchor=tk.CENTER, pady=2)
        
        # GitHub link
        def open_github():
            webbrowser.open("https://github.com/Bell-O")
        
        github_button = ttk.Button(
            card_content,
            text="Visit GitHub",
            command=open_github,
            style='Secondary.TButton'
        )
        github_button.pack(anchor=tk.CENTER, pady=20)
    
    def select_file(self, encrypted=False):
        """Opens a file dialog to select a file"""
        # Get initial directory
        initial_dir = self.app_config.get("last_directory", os.path.expanduser("~"))
        
        # File types
        if encrypted:
            filetypes = [("Encrypted Files", f"*{FILE_EXTENSION}"), ("All Files", "*.*")]
        else:
            filetypes = [("All Files", "*.*")]
        
        # Open file dialog
        file_path = filedialog.askopenfilename(
            initialdir=initial_dir,
            title="Select File",
            filetypes=filetypes
        )
        
        if file_path:
            self.file_path = file_path
            
            # Update file entries
            if encrypted:
                self.decrypt_file_entry.delete(0, tk.END)
                self.decrypt_file_entry.insert(0, file_path)
                self.update_decrypt_file_info()
            else:
                self.file_entry.delete(0, tk.END)
                self.file_entry.insert(0, file_path)
                self.update_file_info()
            
            # Add to recent files
            ConfigManager.add_recent_file(file_path)
    
    def load_recent_file(self, file_path, encrypted=False):
        """Loads a file from the recent files list"""
        if os.path.exists(file_path):
            self.file_path = file_path
            
            # Update file entries
            if encrypted:
                self.decrypt_file_entry.delete(0, tk.END)
                self.decrypt_file_entry.insert(0, file_path)
                self.update_decrypt_file_info()
            else:
                self.file_entry.delete(0, tk.END)
                self.file_entry.insert(0, file_path)
                self.update_file_info()
        else:
            messagebox.showerror("Error", f"File not found: {file_path}")
            
            # Remove from recent files
            recent_files = self.app_config.get("recent_files", [])
            if file_path in recent_files:
                recent_files.remove(file_path)
                self.app_config["recent_files"] = recent_files
                ConfigManager.save_config(self.app_config)
    
    def update_file_info(self):
        """Updates the file information display"""
        if self.file_path and os.path.exists(self.file_path):
            file_size = os.path.getsize(self.file_path)
            size_str = self.format_file_size(file_size)
            file_name = os.path.basename(self.file_path)
            
            self.file_info_var.set(f"File: {file_name} ({size_str})")
        else:
            self.file_info_var.set("No file selected")
    
    def update_decrypt_file_info(self):
        """Updates the encrypted file information display"""
        if self.file_path and os.path.exists(self.file_path):
            file_size = os.path.getsize(self.file_path)
            size_str = self.format_file_size(file_size)
            file_name = os.path.basename(self.file_path)
            
            if file_name.endswith(FILE_EXTENSION):
                original_name = file_name[:-len(FILE_EXTENSION)]
                self.decrypt_file_info_var.set(
                    f"File: {file_name} ({size_str})\nWill decrypt to: {original_name}"
                )
            else:
                self.decrypt_file_info_var.set(
                    f"File: {file_name} ({size_str})\nWarning: Not a standard encrypted file"
                )
        else:
            self.decrypt_file_info_var.set("No file selected")
    
    def format_file_size(self, size_bytes):
        """Formats file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} bytes"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
    
    def check_password_strength(self, *args):
        """Checks and displays password strength"""
        password = self.password_var.get()
        
        if not password:
            self.strength_var.set(0)
            self.strength_text_var.set("")
            return
        
        # Calculate strength
        score = 0
        feedback = []
        
        # Length check
        if len(password) < 8:
            feedback.append("Password is too short")
        else:
            score += min(len(password) * 4, 40)  # Up to 40 points for length
        
        # Character diversity
        if any(c.isupper() for c in password):
            score += 10
        else:
            feedback.append("Add uppercase letters")
            
        if any(c.islower() for c in password):
            score += 10
        else:
            feedback.append("Add lowercase letters")
            
        if any(c.isdigit() for c in password):
            score += 10
        else:
            feedback.append("Add numbers")
            
        if any(not c.isalnum() for c in password):
            score += 15
        else:
            feedback.append("Add special characters")
        
        # Determine color and message
        if score < 40:
            color = ERROR_COLOR
            strength = "Weak"
        elif score < 70:
            color = WARNING_COLOR
            strength = "Moderate"
        else:
            color = SUCCESS_COLOR
            strength = "Strong"
            
        # Create feedback message
        if feedback and score < 70:
            message = f"{strength}: {'; '.join(feedback)}"
        else:
            message = strength
        
        # Update UI
        self.strength_var.set(score)
        self.strength_text_var.set(message)
        self.strength_label.configure(foreground=color)
        
        # Also check if passwords match
        self.check_passwords_match()
    
    def check_passwords_match(self, *args):
        """Checks if passwords match and updates UI"""
        password = self.password_var.get()
        confirm = self.confirm_password_var.get()
        
        if password and confirm:
            if password == confirm:
                self.match_var.set("Passwords match")
                self.match_var.configure(foreground=SUCCESS_COLOR)
            else:
                self.match_var.set("Passwords do not match")
                self.match_var.configure(foreground=ERROR_COLOR)
        else:
            self.match_var.set("")
    
    def toggle_password_visibility(self):
        """Toggles password visibility"""
        show = self.show_password_var.get()
        self.password_entry.configure(show="" if show else "•")
        self.confirm_entry.configure(show="" if show else "•")
    
    def toggle_decrypt_password_visibility(self, var):
        """Toggles decrypt password visibility"""
        show = var.get()
        self.decrypt_password_entry.configure(show="" if show else "•")
    
    def encrypt_file(self):
        """Encrypts the selected file"""
        # Validate inputs
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Error", "Please select a valid file to encrypt.")
            return
        
        password = self.password_var.get()
        confirm = self.confirm_password_var.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        
        # Set output path
        output_path = f"{self.file_path}{FILE_EXTENSION}"
        
        # Check if output file already exists
        if os.path.exists(output_path):
            result = messagebox.askyesno(
                "File Exists", 
                f"The file {os.path.basename(output_path)} already exists. "
                "Do you want to overwrite it?"
            )
            if not result:
                return
        
        # Start encryption in a separate thread
        threading.Thread(
            target=self._encrypt_file_thread,
            args=(self.file_path, output_path, password, self.secure_delete_var.get()),
            daemon=True
        ).start()
    
    def _encrypt_file_thread(self, input_path, output_path, password, secure_delete):
        """Thread function for file encryption"""
        try:
            # Update UI
            self.progress_var.set(0)
            self.progress_text_var.set("Reading file...")
            
            # Read file
            with open(input_path, 'rb') as f:
                file_data = f.read()
            
            # Update progress
            self.progress_var.set(20)
            self.progress_text_var.set("Encrypting data...")
            
            # Encrypt data
            encrypted_data = CryptoService.encrypt_data(file_data, password)
            
            # Update progress
            self.progress_var.set(80)
            self.progress_text_var.set("Writing encrypted file...")
            
            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Update progress
            self.progress_var.set(90)
            
            # Securely delete original if requested
            if secure_delete:
                self.progress_text_var.set("Securely deleting original file...")
                FileHandler.secure_delete(input_path, passes=self.app_config.get("secure_delete_passes", 3))
            
            # Complete
            self.progress_var.set(100)
            self.progress_text_var.set("Encryption complete!")
            
            # Show success message
            messagebox.showinfo(
                "Success", 
                f"File encrypted successfully:\n{output_path}"
            )
            
            # Add to recent files
            ConfigManager.add_recent_file(output_path)
            
        except Exception as e:
            # Handle errors
            self.progress_text_var.set("Encryption failed!")
            messagebox.showerror("Error", f"Error during encryption:\n{e}")
    
    def decrypt_file(self, secure_delete):
        """Decrypts the selected file"""
        # Validate inputs
        if not self.file_path or not os.path.exists(self.file_path):
            messagebox.showerror("Error", "Please select a valid file to decrypt.")
            return
        
        password = self.decrypt_password_entry.get()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        # Set output path
        output_path = self.file_path
        if output_path.endswith(FILE_EXTENSION):
            output_path = output_path[:-len(FILE_EXTENSION)]
        else:
            output_path = f"{output_path}.decrypted"
        
        # Check if output file already exists
        if os.path.exists(output_path):
            result = messagebox.askyesno(
                "File Exists", 
                f"The file {os.path.basename(output_path)} already exists. "
                "Do you want to overwrite it?"
            )
            if not result:
                return
        
        # Start decryption in a separate thread
        threading.Thread(
            target=self._decrypt_file_thread,
            args=(self.file_path, output_path, password, secure_delete),
            daemon=True
        ).start()
    
    def _decrypt_file_thread(self, input_path, output_path, password, secure_delete):
        """Thread function for file decryption"""
        try:
            # Update UI
            self.decrypt_progress_var.set(0)
            self.decrypt_progress_text_var.set("Reading encrypted file...")
            
            # Read encrypted file
            with open(input_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Update progress
            self.decrypt_progress_var.set(20)
            self.decrypt_progress_text_var.set("Decrypting data...")
            
            # Decrypt data
            try:
                decrypted_data = CryptoService.decrypt_data(encrypted_data, password)
            except InvalidTag:
                self.decrypt_progress_text_var.set("Decryption failed: Invalid password")
                messagebox.showerror(
                    "Error", 
                    "Authentication failed: Invalid password or corrupted file."
                )
                return
            
            # Update progress
            self.decrypt_progress_var.set(80)
            self.decrypt_progress_text_var.set("Writing decrypted file...")
            
            # Write decrypted file
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Update progress
            self.decrypt_progress_var.set(90)
            
            # Securely delete encrypted file if requested
            if secure_delete:
                self.decrypt_progress_text_var.set("Securely deleting encrypted file...")
                FileHandler.secure_delete(input_path, passes=self.app_config.get("secure_delete_passes", 3))
            
            # Complete
            self.decrypt_progress_var.set(100)
            self.decrypt_progress_text_var.set("Decryption complete!")
            
            # Show success message
            messagebox.showinfo(
                "Success", 
                f"File decrypted successfully:\n{output_path}"
            )
            
            # Add to recent files
            ConfigManager.add_recent_file(output_path)
            
        except Exception as e:
            # Handle errors
            self.decrypt_progress_text_var.set("Decryption failed!")
            messagebox.showerror("Error", f"Error during decryption:\n{e}")


def main():
    """Main entry point for the application"""
    app = ProfessionalUI()
    app.mainloop()


if __name__ == "__main__":
    main()