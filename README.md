# Secure Vault – All Processes in a Single File

This repository contains a fully integrated application that combines all functions – from password management, note taking, and credit/debit card management to security features such as two-factor authentication, automatic locking, and backups – into a single Python file. The application is developed using PyQt6 as the GUI framework and employs modern cryptographic methods to protect all sensitive data.

## Table of Contents

- [Overview](#overview)
- [Main Features and Workflows](#main-features-and-workflows)
  - [Resource and Data Directories](#resource-and-data-directories)
  - [User Interface and Widgets](#user-interface-and-widgets)
  - [Password Management](#password-management)
  - [Note Management](#note-management)
  - [Credit/Debit Card Management](#creditdebit-card-management)
  - [Two-Factor Authentication (2FA)](#two-factor-authentication-2fa)
  - [Automatic Locking](#automatic-locking)
  - [Backup and Restoration](#backup-and-restoration)
- [Installation and Usage](#installation-and-usage)

## Overview

**Secure Vault** is a multifunctional, security-focused password manager. The application provides:

- **Password Management:** Create, view, edit, and delete password entries.
- **Note Management:** Securely store and manage personal notes.
- **Card Management:** Manage credit and debit card information with an attractive visual display.
- **Data Encryption:** All sensitive data is encrypted using Fernet (with PBKDF2HMAC for key derivation).
- **Two-Factor Authentication:** Optional 2FA with TOTP (via PyOTP) and QR code generation.
- **Automatic Locking:** The application automatically locks after a set period of inactivity.
- **Backup & Restoration:** Export all data as an encrypted backup and restore it when needed.
- **Theming:** Supports dark and light themes for a personalized user interface.

## Main Features and Workflows

All processes are integrated into a single Python file. Below is an explanation of the key functionalities:

### Resource and Data Directories

- **Resource Path:**  
  The function `resource_path(relative_path)` ensures that all required resources (e.g., themes, icons) can be located even after packaging with PyInstaller.
- **Data Directory:**  
  Using `appdirs.user_data_dir`, a cross-platform directory is created to store configurations, encrypted passwords, notes, and card data.

### User Interface and Widgets

- **Modern UI Components:**  
  Custom widgets like `ModernButton`, `ModernLineEdit`, and `ModernLabel` provide a consistent and modern design.
- **Credit Card Widget:**  
  The `CreditCardWidget` visually displays credit/debit card information in an appealing layout.

### Password Management

- **Creation and Storage:**  
  New passwords are saved as encrypted JSON data along with a title and username.  
  - **Encryption:** The entire password database is encrypted using Fernet.
- **Display and Editing:**  
  Saved passwords are displayed in a QTreeWidget, and individual entries can be viewed, edited, or deleted.
- **Password Generator:**  
  The function `generate_password()` creates a secure, random password from a predefined character set.

### Note Management

- **Creation:**  
  New notes (with title and content) can be created and saved via a dialog.
- **Editing and Deletion:**  
  Notes are listed in a QTreeWidget similar to passwords, allowing for editing or deletion.
- **Encryption:**  
  Notes are also stored in an encrypted format using Fernet.

### Credit/Debit Card Management

- **Adding Cards:**  
  Card details (e.g., cardholder name, card number, expiry date, CVV) can be entered through a dialog.
- **Visualization:**  
  The `CreditCardWidget` presents the card information attractively; the card number is partially masked.
- **Security:**  
  All card data is stored in encrypted form.

### Two-Factor Authentication (2FA)

- **Setup:**  
  After setting up the master password, the user can optionally enable 2FA. A secret key is generated, a QR code is created, and the key is also displayed for manual entry.
- **Verification:**  
  When logging in, if 2FA is enabled, a TOTP code is required in addition to the master password for access.

### Automatic Locking

- **Inactivity Timeout:**  
  A `QTimer` is used to automatically lock the application after a defined period of inactivity.
- **Event Filtering:**  
  Mouse and keyboard events reset the timer to prevent accidental locking.

### Backup and Restoration

- **Backup Creation:**  
  All data (passwords, notes, cards) is merged into a combined JSON document, encrypted, and saved as a backup file.
- **Restoration:**  
  A file dialog allows the user to select a backup, decrypt it, and import the data into the application.

## Installation and Usage

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/ChristophBentz/SecureVault.git
   cd securevault

2. **Create a Virtual Environment:**

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate

3. **Install Dependencies:**

   ```bash
   pip install -r requirements.txt

4. **Start the Application:**

   ```bash
   python SecureVault.py or use the .exe in the folder.

