# FlightCodeV2 - Advanced Secure File Encryption

**Version: 2.0**  
FlightCodeV2 is an upgraded version of [FlightCodeV1](https://github.com/Bell-O/FlightCode), featuring enhanced security, better UI/UX, and additional functionalities for file encryption, decryption, and secure deletion.

## 🔥 Features
✅ **AES-GCM Encryption & Decryption** - High-security encryption with Argon2 key derivation  
✅ **GUI & CLI Support** - Choose between a user-friendly interface or command-line control  
✅ **Secure File Deletion (Shred Files)** - Overwrites files before deletion to prevent recovery  
✅ **Password Generator** - Create strong, random passwords  
✅ **Recent Files Management** - Keep track of your encrypted/decrypted files  
✅ **Colorful CLI with ASCII Art** - Enhanced user experience with colors and banners  

## 🔄 What's New in FlightCodeV2?
🚀 **Upgraded GUI (Tkinter)** - More professional and intuitive design  
🚀 **Added Secure File Deletion** - Files can be permanently erased  
🚀 **Optimized CLI Experience** - Improved command-line interactions with better feedback  
🚀 **More Secure Encryption Process** - Optimized Argon2 hashing for password strengthening  
🚀 **Better Performance** - Faster encryption/decryption process  

## 🚀 Installation
### **1. Install Required Packages**
```bash
pip install -r requirements.txt
```

### **2. Run GUI Version**
```bash
python flightcodev2.py
```

### **3. Run CLI Version**
```bash
python flightcodev2CLI.py --help
```

## 🖥️ GUI Usage
1. Open FlightCodeV2 GUI
2. Select a file to encrypt or decrypt
3. Enter a secure password
4. Click "Encrypt" or "Decrypt" to process

## 💻 CLI Usage
```
python flightcodev2CLI.py 

```


## 🛠️ Technology Stack
- **Python**
- **Tkinter** (GUI)
- **Argparse + Colorama** (CLI)
- **Cryptography** (AES-GCM, Argon2)
- **Pillow (PIL)** (UI Image Handling)

## 🎯 Future Plans
- Support for encrypted file sharing
- Cloud integration for encrypted file backup
- Improved UX/UI for GUI version

## 📜 License
This project is licensed under the Bell Software License (BSL). See the LICENSE file for details.

## 🤝 Contributing
Pull requests are welcome! Please ensure your changes are well-documented.

---
Developed by [Bell-O](https://github.com/Bell-O) 🚀

