import sys
import os
import json
import base64
import hashlib
import secrets
import re
import requests
import pyotp
import qrcode
import shutil
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QMessageBox, QDialog, QFormLayout, QCheckBox,
    QFrame, QSplitter, QStackedWidget, QToolButton, QInputDialog, QSizePolicy, QFileDialog, QSpinBox, QCompleter,
    QTextEdit
)
from PyQt6.QtCore import Qt, QSize, QTimer, QEvent
from PyQt6.QtGui import QPixmap, QImage, QIcon

from appdirs import user_data_dir

def resource_path(relative_path):
    """Returns the absolute path to the resource – works also with PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# For persistent data directories
APP_NAME = "SecureVault"
APP_AUTHOR = "Jumpy.gg"
data_dir = user_data_dir(APP_NAME, APP_AUTHOR)
if not os.path.exists(data_dir):
    os.makedirs(data_dir)

VERSION_LABEL_HEIGHT = 200 

# ---------------------------
# A widget to display a credit/debit card
class CreditCardWidget(QFrame):
    def __init__(self, card_holder, card_number, expiry_date, parent=None):
        super().__init__(parent)
        self.card_holder = card_holder
        self.card_number = card_number
        self.expiry_date = expiry_date
        self.init_ui()

    def init_ui(self):
        self.setMinimumSize(400, 250)
        # Style similar to the CodePen example – adjust as desired!
        self.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e3c72, stop:1 #2a5298);
                border-radius: 15px;
                padding: 20px;
            }
            QLabel {
                color: white;
                font-family: 'Arial';
            }
        """)
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.addStretch()
        # Display the card number formatted in groups of 4 digits
        self.card_number_label = QLabel(self.format_card_number(self.card_number))
        self.card_number_label.setStyleSheet("font-size: 24pt; letter-spacing: 4px;")
        layout.addWidget(self.card_number_label, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        bottom_layout = QHBoxLayout()
        self.card_holder_label = QLabel(self.card_holder.upper())
        self.card_holder_label.setStyleSheet("font-size: 14pt;")
        self.expiry_label = QLabel("EXP: " + self.expiry_date)
        self.expiry_label.setStyleSheet("font-size: 12pt;")
        bottom_layout.addWidget(self.card_holder_label)
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.expiry_label)
        layout.addLayout(bottom_layout)

    def format_card_number(self, number):
        # Groups the card number in blocks of four
        return " ".join(number[i:i+4] for i in range(0, len(number), 4))

# ---------------------------
# Other code (password, notes & backup functionality)
class ModernButton(QPushButton):
    def __init__(self, text, parent=None, primary=True):
        super().__init__(text, parent)
        self.setMinimumHeight(40)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        if primary:
            self.setObjectName("primaryButton")
        else:
            self.setObjectName("secondaryButton")

class ModernLineEdit(QLineEdit):
    def __init__(self, parent=None, placeholder=""):
        super().__init__(parent)
        self.setMinimumHeight(40)
        self.setMinimumWidth(300)
        self.setPlaceholderText(placeholder)

class ModernLabel(QLabel):
    def __init__(self, text, parent=None, is_title=False):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        if is_title:
            self.setObjectName("titleLabel")
        else:
            self.setObjectName("normalLabel")

class PasswordManager(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secure Vault - Password Manager")
        self.setWindowIcon(QIcon(resource_path("icon.png")))
        self.setGeometry(100, 100, 1000, 650)
        self.config_file = os.path.join(data_dir, "config.json")
        self.password_file = os.path.join(data_dir, "passwords.enc")
        self.notes_file = os.path.join(data_dir, "notes.enc")
        self.cards_file = os.path.join(data_dir, "cards.enc")
        self.key = None
        self.current_theme = "dark"
        self.auto_lock_timeout = 45
        self.inactivity_timer = None
        self.init_ui()
        app = QApplication.instance()
        if app:
            app.installEventFilter(self)

    def init_ui(self):
        self.show_start_screen()

    def show_message(self, title, message, icon=QMessageBox.Icon.Information):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(icon)
        msg_box.setStyleSheet("QLabel{min-width: 250px;}")
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        msg_box.exec()

    def update_completers(self):
        passwords = self.get_passwords()
        titles = list({data.get("title", "") for data in passwords.values() if data.get("title", "")})
        usernames = list({data.get("username", "") for data in passwords.values() if data.get("username", "")})
        title_completer = QCompleter(titles)
        username_completer = QCompleter(usernames)
        self.title_entry.setCompleter(title_completer)
        self.username_entry.setCompleter(username_completer)

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress, QEvent.Type.KeyPress):
            if self.inactivity_timer is not None:
                self.inactivity_timer.start(self.auto_lock_timeout * 1000)
        return super().eventFilter(obj, event)

    def auto_lock(self):
        if self.inactivity_timer is not None:
            self.inactivity_timer.stop()
        self.show_message("Auto Lock", "Due to inactivity, the session has been automatically locked.", QMessageBox.Icon.Information)
        self.show_login_screen()

    def get_theme_icon(self):
        return "🌙" if self.current_theme == "light" else "☀"

    def toggle_theme(self):
        if self.current_theme == "light":
            self.current_theme = "dark"
            try:
                with open(resource_path("dark.qss"), "r") as f:
                    self.setStyleSheet(f.read())
            except Exception as e:
                self.show_message("Error", f"Dark theme could not be loaded: {str(e)}", QMessageBox.Icon.Critical)
        else:
            self.current_theme = "light"
            try:
                with open(resource_path("light.qss"), "r") as f:
                    self.setStyleSheet(f.read())
            except Exception as e:
                self.show_message("Error", f"Light theme could not be loaded: {str(e)}", QMessageBox.Icon.Critical)

    def show_start_screen(self):
        if self.centralWidget():
            self.centralWidget().deleteLater()
        start_widget = QWidget()
        self.setCentralWidget(start_widget)
        top_bar = QHBoxLayout()
        top_bar.setContentsMargins(10, 10, 10, 10)
        self.theme_toggle_button = QToolButton()
        self.theme_toggle_button.setText(self.get_theme_icon())
        self.theme_toggle_button.setToolTip("Switch theme")
        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        top_bar.addWidget(self.theme_toggle_button, alignment=Qt.AlignmentFlag.AlignLeft)
        top_bar.addStretch()
        main_layout = QVBoxLayout(start_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addLayout(top_bar)
        container = QWidget()
        container.setObjectName("glassContainer")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 40, 40, 40)
        title = ModernLabel("Welcome to Secure Vault", is_title=True)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)
        container_layout.addSpacing(20)
        subtitle = ModernLabel("Please choose an option", is_title=False)
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(subtitle)
        container_layout.addSpacing(30)
        button_layout = QVBoxLayout()
        login_button = ModernButton("I already have an account")
        create_button = ModernButton("Create a new account")
        login_button.clicked.connect(self.handle_login_option)
        create_button.clicked.connect(self.handle_create_account_option)
        button_layout.addWidget(login_button)
        button_layout.addSpacing(20)
        button_layout.addWidget(create_button)
        container_layout.addLayout(button_layout)
        main_layout.addStretch()
        main_layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch()

    def handle_login_option(self):
        if os.path.exists(self.config_file):
            self.show_login_screen()
        else:
            self.show_message("No Account Found", "No account was found. Please create a new account.", QMessageBox.Icon.Information)
            self.show_setup_screen()

    def handle_create_account_option(self):
        if os.path.exists(self.config_file):
            reply = QMessageBox.question(
                self,
                "Account Already Exists",
                "An account already exists. Do you want to create a new account? This will overwrite all existing data.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.show_setup_screen()
            else:
                self.show_login_screen()
        else:
            self.show_setup_screen()

    def check_password_strength(self, password):
        strength = 0
        if len(password) >= 8:
            strength += 1
        if re.search(r'\d', password):
            strength += 1
        if re.search(r'[A-Z]', password):
            strength += 1
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            strength += 1
        return strength

    def check_password_leak(self, password):
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url)
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    return int(count)
        return 0

    def evaluate_password_health(self, password):
        strength = self.check_password_strength(password)
        leak_count = self.check_password_leak(password)
        health_status = {
            'strength': strength,
            'leak_count': leak_count,
            'recommendations': []
        }
        if strength < 3:
            health_status['recommendations'].append("The password is too weak. Use at least 8 characters including numbers, uppercase letters, and special characters.")
        if leak_count > 0:
            health_status['recommendations'].append(f"The password was found in {leak_count} data breaches. It is strongly recommended to change the password.")
        return health_status

    def show_password_health(self):
        selected_items = self.tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select an entry!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        password_id = item.data(0, Qt.ItemDataRole.UserRole)
        passwords = self.get_passwords()
        if password_id in passwords:
            health_status = self.evaluate_password_health(passwords[password_id]["password"])
            dialog = QDialog(self)
            dialog.setWindowTitle("Password Health")
            dialog.setMinimumWidth(450)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            layout.addWidget(ModernLabel("Password Health", is_title=True))
            info_layout = QFormLayout()
            info_layout.addRow(ModernLabel("Strength:"), ModernLabel(f"{health_status['strength']}/4"))
            info_layout.addRow(ModernLabel("Leaked Occurrences:"), ModernLabel(f"{health_status['leak_count']}"))
            layout.addLayout(info_layout)
            if health_status['recommendations']:
                layout.addWidget(ModernLabel("Recommendations:"))
                for rec in health_status['recommendations']:
                    layout.addWidget(ModernLabel(f"- {rec}"))
            close_button = ModernButton("Close", primary=False)
            close_button.clicked.connect(dialog.accept)
            layout.addWidget(close_button)
            dialog.exec()

    def create_backup(self):
        passwords = self.get_passwords()
        notes = self.get_notes()
        cards = self.get_cards()
        if not passwords and not notes and not cards:
            self.show_message("Backup Not Possible", "There is currently no data available to backup.\nPlease add passwords, notes, or cards first.", QMessageBox.Icon.Information)
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"securevault_backup_{timestamp}.enc"
        try:
            combined_data = {
                "passwords": passwords,
                "notes": notes,
                "cards": cards
            }
            combined_json = json.dumps(combined_data)
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            backup_password, ok = QInputDialog.getText(
                self,
                "Backup Password",
                "Enter the backup password:",
                QLineEdit.EchoMode.Password
            )
            backup_password = backup_password.strip()
            if not ok or not backup_password:
                self.show_message("Error", "Backup password is required!", QMessageBox.Icon.Warning)
                return
            backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode('utf-8')))
            cipher_backup = Fernet(backup_key)
            encrypted_backup = cipher_backup.encrypt(combined_json.encode('utf-8'))
            backup_data = {
                "salt": base64.b64encode(salt).decode('utf-8'),
                "data": encrypted_backup.decode('utf-8')
            }
            with open(backup_file, 'w') as f:
                json.dump(backup_data, f)
            self.show_message("Backup Created", f"Backup successfully created: {backup_file}", QMessageBox.Icon.Information)
        except Exception as e:
            self.show_message("Error", f"Error creating backup: {str(e)}", QMessageBox.Icon.Critical)

    def restore_backup(self):
        backup_file, _ = QFileDialog.getOpenFileName(
            self,
            "Select Backup File",
            "",
            "Encrypted Backup Files (*.enc);;All Files (*)"
        )
        if not backup_file:
            return
        backup_password, ok = QInputDialog.getText(
            self,
            "Backup Password",
            "Enter the backup password:",
            QLineEdit.EchoMode.Password
        )
        backup_password = backup_password.strip()
        if not ok or not backup_password:
            self.show_message("Error", "Backup password is required!", QMessageBox.Icon.Warning)
            return
        try:
            with open(backup_file, 'r') as f:
                backup_data = json.load(f)
            salt = base64.b64decode(backup_data["salt"])
            encrypted_data = backup_data["data"].encode('utf-8')
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            backup_key = base64.urlsafe_b64encode(kdf.derive(backup_password.encode('utf-8')))
            cipher_backup = Fernet(backup_key)
            decrypted_json = cipher_backup.decrypt(encrypted_data).decode('utf-8')
            combined_data = json.loads(decrypted_json)
            master_cipher = Fernet(self.key)
            passwords_encrypted = master_cipher.encrypt(json.dumps(combined_data.get("passwords", {})).encode('utf-8'))
            notes_encrypted = master_cipher.encrypt(json.dumps(combined_data.get("notes", {})).encode('utf-8'))
            cards_encrypted = master_cipher.encrypt(json.dumps(combined_data.get("cards", {})).encode('utf-8'))
            with open(self.password_file, 'w') as f:
                f.write(passwords_encrypted.decode('utf-8'))
            with open(self.notes_file, 'w') as f:
                f.write(notes_encrypted.decode('utf-8'))
            with open(self.cards_file, 'w') as f:
                f.write(cards_encrypted.decode('utf-8'))
            self.show_message("Backup Restored", "Backup successfully restored!", QMessageBox.Icon.Information)
            self.load_passwords()
            self.load_notes()
            self.load_cards()
        except Exception as e:
            self.show_message("Error", f"Error restoring backup: {str(e)}", QMessageBox.Icon.Critical)

    def show_setup_screen(self):
        if self.centralWidget():
            self.centralWidget().deleteLater()
        setup_widget = QWidget()
        self.setCentralWidget(setup_widget)
        main_layout = QVBoxLayout(setup_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        container = QWidget()
        container.setObjectName("glassContainer")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 40, 40, 40)
        logo_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_layout.addStretch()
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch()
        container_layout.addLayout(logo_layout)
        title = ModernLabel("Welcome to Secure Vault", is_title=True)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)
        subtitle = ModernLabel("Create a master password to protect your passwords")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(subtitle)
        container_layout.addSpacing(30)
        form_layout = QFormLayout()
        form_layout.setSpacing(15)
        self.password_entry = ModernLineEdit(placeholder="Enter master password")
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_entry = ModernLineEdit(placeholder="Confirm master password")
        self.confirm_entry.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow(self.password_entry)
        form_layout.addRow(self.confirm_entry)
        container_layout.addLayout(form_layout)
        container_layout.addSpacing(30)
        create_button = ModernButton("Create Secure Vault")
        create_button.clicked.connect(self.create_master_password)
        container_layout.addWidget(create_button)
        hint = ModernLabel("The master password should be at least 8 characters long and include numbers and special characters.")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setWordWrap(True)
        container_layout.addSpacing(20)
        container_layout.addWidget(hint)
        main_layout.addStretch()
        main_layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch()

    def create_master_password(self):
        password = self.password_entry.text()
        confirm = self.confirm_entry.text()
        if password != confirm:
            self.show_message("Error", "Passwords do not match!", QMessageBox.Icon.Critical)
            return
        if len(password) < 8:
            self.show_message("Error", "The password must be at least 8 characters long!", QMessageBox.Icon.Critical)
            return
        salt = os.urandom(16)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        config = {
            "password_hash": base64.b64encode(password_hash).decode('utf-8'),
            "salt": base64.b64encode(salt).decode('utf-8'),
            "is_two_factor_enabled": False,
            "secret_token": None,
            "auto_lock_timeout": 45
        }
        with open(self.config_file, 'w') as f:
            json.dump(config, f)
        setup_2fa = QMessageBox.question(
            self,
            "Two-Factor Authentication",
            "Would you like to enable two-factor authentication?\n\nThis will greatly enhance the security of your password manager.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if setup_2fa == QMessageBox.StandardButton.Yes:
            self.setup_two_factor()
        else:
            self.show_message("Success", "Master password successfully created!", QMessageBox.Icon.Information)
            self.show_login_screen()

    def setup_two_factor(self):
        secret_key = pyotp.random_base32()
        totp = pyotp.TOTP(secret_key)
        uri = totp.provisioning_uri(name="SecureVault", issuer_name="Secure Vault")
        qr = qrcode.make(uri)
        buffer = BytesIO()
        qr.save(buffer, format="PNG")
        qr_image = QImage.fromData(buffer.getvalue())
        qr_pixmap = QPixmap.fromImage(qr_image)
        dialog = QDialog(self)
        dialog.setWindowTitle("Set Up Two-Factor Authentication")
        dialog.setMinimumWidth(450)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(30, 30, 30, 30)
        title_label = ModernLabel("Two-Factor Authentication", is_title=True)
        layout.addWidget(title_label)
        instructions = ModernLabel("Scan the QR code with your authenticator app (e.g., Google Authenticator, Authy) and then enter the generated code to complete the setup.")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        layout.addSpacing(20)
        qr_label = QLabel()
        qr_label.setPixmap(qr_pixmap.scaled(200, 200, Qt.AspectRatioMode.KeepAspectRatio))
        qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(qr_label)
        layout.addSpacing(10)
        key_layout = QHBoxLayout()
        key_label = ModernLabel("Manual key:")
        key_value = ModernLabel(secret_key)
        key_value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        key_layout.addWidget(key_label)
        key_layout.addWidget(key_value)
        layout.addLayout(key_layout)
        layout.addSpacing(20)
        form_layout = QFormLayout()
        code_entry = ModernLineEdit(placeholder="6-digit code")
        form_layout.addRow(ModernLabel("Verification code:"), code_entry)
        layout.addLayout(form_layout)
        layout.addSpacing(20)
        buttons_layout = QHBoxLayout()
        verify_button = ModernButton("Verify")
        cancel_button = ModernButton("Cancel", primary=False)
        buttons_layout.addStretch()
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(verify_button)
        layout.addLayout(buttons_layout)
        cancel_button.clicked.connect(dialog.reject)
        verify_button.clicked.connect(lambda: self.verify_two_factor_setup(dialog, secret_key, code_entry.text()))
        result = dialog.exec()
        if result == QDialog.DialogCode.Rejected:
            self.show_login_screen()

    def verify_two_factor_setup(self, dialog, secret_key, code):
        totp = pyotp.TOTP(secret_key)
        if totp.verify(code):
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            config["is_two_factor_enabled"] = True
            config["secret_token"] = secret_key
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
            dialog.accept()
            self.show_message("Success", "Two-factor authentication successfully enabled!", QMessageBox.Icon.Information)
            self.show_login_screen()
        else:
            self.show_message("Error", "The code entered is invalid. Please try again.", QMessageBox.Icon.Critical)

    def show_login_screen(self):
        if self.centralWidget():
            self.centralWidget().deleteLater()
        login_widget = QWidget()
        self.setCentralWidget(login_widget)
        main_layout = QVBoxLayout(login_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        container = QWidget()
        container.setObjectName("glassContainer")
        container.setFixedWidth(400)
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(40, 40, 40, 40)
        logo_layout = QHBoxLayout()
        logo_label = QLabel()
        logo_layout.addStretch()
        logo_layout.addWidget(logo_label)
        logo_layout.addStretch()
        container_layout.addLayout(logo_layout)
        title = ModernLabel("Secure Vault", is_title=True)
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(title)
        subtitle = ModernLabel("Enter your master password")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        container_layout.addWidget(subtitle)
        container_layout.addSpacing(30)
        self.login_password_entry = ModernLineEdit(placeholder="Master password")
        self.login_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        container_layout.addWidget(self.login_password_entry)
        container_layout.addSpacing(20)
        login_button = ModernButton("Unlock")
        login_button.clicked.connect(self.verify_master_password)
        container_layout.addWidget(login_button)
        main_layout.addStretch()
        main_layout.addWidget(container, alignment=Qt.AlignmentFlag.AlignCenter)
        main_layout.addStretch()
        self.login_password_entry.returnPressed.connect(self.verify_master_password)

    def verify_master_password(self):
        password = self.login_password_entry.text()
        if not os.path.exists(self.config_file):
            self.show_message("Error", "Configuration file is missing!", QMessageBox.Icon.Critical)
            return
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            stored_hash = base64.b64decode(config["password_hash"])
            salt = base64.b64decode(config["salt"])
            is_two_factor_enabled = config.get("is_two_factor_enabled", False)
            password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            if password_hash == stored_hash:
                if is_two_factor_enabled and config.get("secret_token"):
                    self.prompt_for_two_factor(config["secret_token"])
                else:
                    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
                    self.key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
                    self.show_dashboard()
            else:
                self.show_message("Error", "Incorrect password!", QMessageBox.Icon.Critical)
        except Exception as e:
            self.show_message("Error", f"Error reading configuration file: {str(e)}", QMessageBox.Icon.Critical)

    def prompt_for_two_factor(self, secret_token):
        dialog = QDialog(self)
        dialog.setWindowTitle("Two-Factor Authentication")
        dialog.setMinimumWidth(400)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(30, 30, 30, 30)
        title_label = ModernLabel("Two-Factor Code", is_title=True)
        layout.addWidget(title_label)
        instructions = ModernLabel("Please enter the 6-digit code from your authenticator app.")
        instructions.setWordWrap(True)
        layout.addWidget(instructions)
        layout.addSpacing(20)
        code_entry = ModernLineEdit(placeholder="6-digit code")
        layout.addWidget(code_entry)
        layout.addSpacing(20)
        buttons_layout = QHBoxLayout()
        verify_button = ModernButton("Verify")
        cancel_button = ModernButton("Cancel", primary=False)
        buttons_layout.addStretch()
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(verify_button)
        layout.addLayout(buttons_layout)
        cancel_button.clicked.connect(dialog.reject)
        verify_button.clicked.connect(lambda: self.verify_two_factor_code(dialog, secret_token, code_entry.text()))
        code_entry.returnPressed.connect(lambda: self.verify_two_factor_code(dialog, secret_token, code_entry.text()))
        result = dialog.exec()
        if result == QDialog.DialogCode.Rejected:
            self.show_login_screen()

    def verify_two_factor_code(self, dialog, secret_token, code):
        totp = pyotp.TOTP(secret_token)
        if totp.verify(code):
            dialog.accept()
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            salt = base64.b64decode(config["salt"])
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
            self.key = base64.urlsafe_b64encode(kdf.derive(self.login_password_entry.text().encode('utf-8')))
            self.show_dashboard()
        else:
            self.show_message("Error", "The code entered is invalid. Please try again.", QMessageBox.Icon.Critical)

    def show_dashboard(self):
        if self.centralWidget():
            self.centralWidget().deleteLater()
        dashboard = QWidget()
        self.setCentralWidget(dashboard)
        main_layout = QHBoxLayout(dashboard)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(220)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(15, 30, 15, 30)
        sidebar_layout.setSpacing(10)
        title_layout = QHBoxLayout()
        title_label = ModernLabel("Secure Vault", is_title=True)
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        sidebar_layout.addLayout(title_layout)
        sidebar_layout.addSpacing(30)
        self.passwords_button = ModernButton("All Passwords", primary=False)
        self.passwords_button.setObjectName("navButton")
        self.passwords_button.setCheckable(True)
        self.passwords_button.setChecked(True)
        self.add_button = ModernButton("New Password", primary=False)
        self.add_button.setObjectName("navButton")
        self.add_button.setCheckable(True)
        self.notes_button = ModernButton("Notes", primary=False)
        self.notes_button.setObjectName("navButton")
        self.notes_button.setCheckable(True)
        self.cards_button = ModernButton("Cards", primary=False)
        self.cards_button.setObjectName("navButton")
        self.cards_button.setCheckable(True)
        self.settings_button = ModernButton("Settings", primary=False)
        self.settings_button.setObjectName("navButton")
        self.settings_button.setCheckable(True)
        self.backup_button = ModernButton("Backups", primary=False)
        self.backup_button.setObjectName("navButton")
        self.backup_button.setCheckable(True)
        sidebar_layout.addWidget(self.passwords_button)
        sidebar_layout.addWidget(self.add_button)
        sidebar_layout.addWidget(self.notes_button)
        sidebar_layout.addWidget(self.cards_button)
        sidebar_layout.addWidget(self.settings_button)
        sidebar_layout.addWidget(self.backup_button)
        version_label = ModernLabel("Version Alpha 0.0.5", is_title=False)
        version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_label.setStyleSheet("font-size: 10pt; color: #888888;")
        version_label.setFixedHeight(VERSION_LABEL_HEIGHT)
        sidebar_layout.addWidget(version_label)
        sidebar_layout.addStretch()
        logout_button = ModernButton("Log Out", primary=False)
        logout_button.setObjectName("logoutButton")
        logout_button.clicked.connect(self.show_login_screen)
        sidebar_layout.addWidget(logout_button)
        content_area = QWidget()
        content_area.setObjectName("contentArea")
        content_layout = QVBoxLayout(content_area)
        content_layout.setContentsMargins(30, 30, 30, 30)
        self.stacked_widget = QStackedWidget()
        # Index 0: Password list
        passwords_widget = QWidget()
        passwords_layout = QVBoxLayout(passwords_widget)
        header_layout = QHBoxLayout()
        header_label = ModernLabel("Your saved passwords", is_title=True)
        header_layout.addWidget(header_label)
        header_layout.addStretch()
        quick_add_button = ModernButton("+ New Password")
        quick_add_button.clicked.connect(lambda: self.stacked_widget.setCurrentIndex(1))
        quick_add_button.clicked.connect(lambda: self.add_button.setChecked(True))
        quick_add_button.clicked.connect(lambda: self.passwords_button.setChecked(False))
        quick_add_button.clicked.connect(lambda: self.settings_button.setChecked(False))
        quick_add_button.clicked.connect(lambda: self.notes_button.setChecked(False))
        header_layout.addWidget(quick_add_button)
        passwords_layout.addLayout(header_layout)
        self.filter_line_edit = ModernLineEdit(placeholder="Filter: e.g. Google, Amazon...")
        self.filter_line_edit.textChanged.connect(self.load_passwords)
        passwords_layout.addWidget(self.filter_line_edit)
        passwords_layout.addSpacing(10)
        self.tree = QTreeWidget()
        self.tree.setObjectName("passwordTree")
        self.tree.setHeaderLabels(["Title", "Username"])
        self.tree.setColumnWidth(0, 300)
        self.tree.setAlternatingRowColors(False)
        self.tree.setRootIsDecorated(False)
        self.tree.setIndentation(0)
        passwords_layout.addWidget(self.tree)
        action_layout = QHBoxLayout()
        view_button = ModernButton("View", primary=False)
        view_button.clicked.connect(self.view_password)
        edit_button = ModernButton("Edit", primary=False)
        edit_button.clicked.connect(self.edit_password)
        delete_button = ModernButton("Delete", primary=False)
        delete_button.setObjectName("dangerButton")
        delete_button.clicked.connect(self.delete_password)
        health_button = ModernButton("Health", primary=False)
        health_button.clicked.connect(self.show_password_health)
        action_layout.addWidget(view_button)
        action_layout.addWidget(edit_button)
        action_layout.addWidget(delete_button)
        action_layout.addWidget(health_button)
        action_layout.addStretch()
        passwords_layout.addSpacing(15)
        passwords_layout.addLayout(action_layout)
        # Index 1: Add new password
        add_password_widget = QWidget()
        add_layout = QVBoxLayout(add_password_widget)
        add_header = ModernLabel("Add new password", is_title=True)
        add_layout.addWidget(add_header)
        add_layout.addSpacing(20)
        form_widget = QWidget()
        form_widget.setObjectName("formContainer")
        form_layout = QFormLayout(form_widget)
        form_layout.setSpacing(15)
        form_layout.setContentsMargins(25, 25, 25, 25)
        self.title_entry = ModernLineEdit(placeholder="e.g. Google, Amazon, Netflix")
        self.username_entry = ModernLineEdit(placeholder="Username or email")
        self.password_entry = ModernLineEdit(placeholder="Password")
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        password_field_layout = QHBoxLayout()
        password_field_layout.setSpacing(10)
        password_field_layout.addWidget(self.password_entry)
        show_password = QCheckBox("Show")
        show_password.toggled.connect(lambda checked: self.password_entry.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password))
        password_field_layout.addWidget(show_password)
        form_layout.addRow(self.title_entry)
        form_layout.addRow(self.username_entry)
        form_layout.addRow(password_field_layout)
        add_layout.addWidget(form_widget)
        add_layout.addSpacing(20)
        buttons_layout = QHBoxLayout()
        generate_button = ModernButton("Generate secure password", primary=False)
        generate_button.clicked.connect(self.generate_and_set_password)
        save_button = ModernButton("Save password")
        save_button.clicked.connect(self.save_new_password)
        buttons_layout.addWidget(generate_button)
        buttons_layout.addStretch()
        buttons_layout.addWidget(save_button)
        add_layout.addLayout(buttons_layout)
        add_layout.addStretch()
        # Index 2: Notes
        notes_widget = QWidget()
        notes_layout = QVBoxLayout(notes_widget)
        header_layout_notes = QHBoxLayout()
        header_label_notes = ModernLabel("Your notes", is_title=True)
        header_layout_notes.addWidget(header_label_notes)
        header_layout_notes.addStretch()
        quick_add_note_button = ModernButton("+ New Note")
        quick_add_note_button.clicked.connect(self.show_add_note_dialog)
        header_layout_notes.addWidget(quick_add_note_button)
        notes_layout.addLayout(header_layout_notes)
        self.notes_filter_line_edit = ModernLineEdit(placeholder="Filter: e.g. tasks, ideas...")
        self.notes_filter_line_edit.textChanged.connect(self.load_notes)
        notes_layout.addWidget(self.notes_filter_line_edit)
        notes_layout.addSpacing(10)
        self.notes_tree = QTreeWidget()
        self.notes_tree.setObjectName("notesTree")
        self.notes_tree.setHeaderLabels(["Title"])
        self.notes_tree.setColumnWidth(0, 300)
        self.notes_tree.setAlternatingRowColors(False)
        self.notes_tree.setRootIsDecorated(False)
        self.notes_tree.setIndentation(0)
        notes_layout.addWidget(self.notes_tree)
        action_layout_notes = QHBoxLayout()
        view_note_button = ModernButton("View", primary=False)
        view_note_button.clicked.connect(self.view_note)
        edit_note_button = ModernButton("Edit", primary=False)
        edit_note_button.clicked.connect(self.edit_note)
        delete_note_button = ModernButton("Delete", primary=False)
        delete_note_button.setObjectName("dangerButton")
        delete_note_button.clicked.connect(self.delete_note)
        action_layout_notes.addWidget(view_note_button)
        action_layout_notes.addWidget(edit_note_button)
        action_layout_notes.addWidget(delete_note_button)
        action_layout_notes.addStretch()
        notes_layout.addSpacing(15)
        notes_layout.addLayout(action_layout_notes)
        # Index 5: Cards
        cards_widget = QWidget()
        cards_layout = QVBoxLayout(cards_widget)
        header_layout_cards = QHBoxLayout()
        header_label_cards = ModernLabel("Your saved cards", is_title=True)
        header_layout_cards.addWidget(header_label_cards)
        header_layout_cards.addStretch()
        quick_add_card_button = ModernButton("+ New Card")
        quick_add_card_button.clicked.connect(self.show_add_card_dialog)
        header_layout_cards.addWidget(quick_add_card_button)
        cards_layout.addLayout(header_layout_cards)
        # Add filter field for cards:
        self.cards_filter_line_edit = ModernLineEdit(placeholder="Filter: e.g. Visa, MasterCard...")
        self.cards_filter_line_edit.textChanged.connect(self.load_cards)
        cards_layout.addWidget(self.cards_filter_line_edit)
        cards_layout.addSpacing(10)
        self.cards_tree = QTreeWidget()
        self.cards_tree.setObjectName("cardsTree")
        self.cards_tree.setHeaderLabels(["Cardholder", "Card Number"])
        self.cards_tree.setColumnWidth(0, 300)
        self.cards_tree.setAlternatingRowColors(False)
        self.cards_tree.setRootIsDecorated(False)
        self.cards_tree.setIndentation(0)
        cards_layout.addWidget(self.cards_tree)
        action_layout_cards = QHBoxLayout()
        view_card_button = ModernButton("View", primary=False)
        view_card_button.clicked.connect(self.view_card)
        edit_card_button = ModernButton("Edit", primary=False)
        edit_card_button.clicked.connect(self.edit_card)
        delete_card_button = ModernButton("Delete", primary=False)
        delete_card_button.setObjectName("dangerButton")
        delete_card_button.clicked.connect(self.delete_card)
        action_layout_cards.addWidget(view_card_button)
        action_layout_cards.addWidget(edit_card_button)
        action_layout_cards.addWidget(delete_card_button)
        action_layout_cards.addStretch()
        cards_layout.addSpacing(15)
        cards_layout.addLayout(action_layout_cards)
        # Index 3: Settings
        settings_widget = QWidget()
        settings_layout = QVBoxLayout(settings_widget)
        settings_header = ModernLabel("Security Settings", is_title=True)
        settings_layout.addWidget(settings_header)
        settings_layout.addSpacing(20)
        form_widget_settings = QWidget()
        form_widget_settings.setObjectName("formContainer")
        form_layout_settings = QVBoxLayout(form_widget_settings)
        form_layout_settings.setSpacing(15)
        form_layout_settings.setContentsMargins(25, 25, 25, 25)
        with open(self.config_file, 'r') as f:
            config = json.load(f)
        is_two_factor_enabled = config.get("is_two_factor_enabled", False)
        status_layout = QHBoxLayout()
        status_label = ModernLabel("Two-Factor Authentication:")
        status_value = ModernLabel("Enabled" if is_two_factor_enabled else "Disabled")
        status_value.setObjectName("statusLabel")
        status_layout.addWidget(status_label)
        status_layout.addWidget(status_value)
        status_layout.addStretch()
        form_layout_settings.addLayout(status_layout)
        form_layout_settings.addSpacing(10)
        button_layout_settings = QHBoxLayout()
        if is_two_factor_enabled:
            disable_button = ModernButton("Disable 2FA", primary=False)
            disable_button.setObjectName("dangerButton")
            disable_button.clicked.connect(self.disable_two_factor)
            button_layout_settings.addWidget(disable_button)
        else:
            enable_button = ModernButton("Enable 2FA")
            enable_button.clicked.connect(self.setup_two_factor)
            button_layout_settings.addWidget(enable_button)
        button_layout_settings.addStretch()
        form_layout_settings.addLayout(button_layout_settings)
        theme_button = ModernButton("Switch theme")
        theme_button.clicked.connect(self.toggle_theme)
        form_layout_settings.addWidget(theme_button)
        autolock_layout = QHBoxLayout()
        autolock_label = ModernLabel("Auto-Lock Time (seconds):")
        self.autolock_spinbox = QSpinBox()
        self.autolock_spinbox.setMinimum(10)
        self.autolock_spinbox.setMaximum(600)
        default_autolock = config.get("auto_lock_timeout", 45)
        self.autolock_spinbox.setValue(default_autolock)
        self.autolock_spinbox.setStyleSheet("""
            QSpinBox {
                border: 1px solid #424242;
                border-radius: 6px;
                padding: 4px 8px;
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QSpinBox:focus {
                border: 1px solid #00897B;
            }
            QSpinBox::up-button, QSpinBox::down-button {
                border: none;
                background: none;
            }
        """)
        autolock_layout.addWidget(autolock_label)
        autolock_layout.addWidget(self.autolock_spinbox)
        autolock_layout.addStretch()
        form_layout_settings.addLayout(autolock_layout)
        save_settings_button = ModernButton("Save settings")
        save_settings_button.clicked.connect(self.save_settings)
        form_layout_settings.addWidget(save_settings_button)
        settings_layout.addWidget(form_widget_settings)
        settings_layout.addStretch()
        # Index 4: Backups
        backup_widget = QWidget()
        backup_layout = QVBoxLayout(backup_widget)
        backup_header = ModernLabel("Backups", is_title=True)
        backup_layout.addWidget(backup_header)
        backup_layout.addSpacing(20)
        backup_instructions = ModernLabel("Here you can create and restore a combined backup of your passwords, notes, and cards.")
        backup_instructions.setWordWrap(True)
        backup_layout.addWidget(backup_instructions)
        backup_layout.addSpacing(20)
        create_backup_button = ModernButton("Create Backup")
        create_backup_button.clicked.connect(self.create_backup)
        restore_backup_button = ModernButton("Restore Backup")
        restore_backup_button.clicked.connect(self.restore_backup)
        backup_layout.addWidget(create_backup_button)
        backup_layout.addWidget(restore_backup_button)
        backup_layout.addStretch()
        self.stacked_widget.addWidget(passwords_widget)     # Index 0
        self.stacked_widget.addWidget(add_password_widget)    # Index 1
        self.stacked_widget.addWidget(notes_widget)           # Index 2
        self.stacked_widget.addWidget(settings_widget)        # Index 3
        self.stacked_widget.addWidget(backup_widget)          # Index 4
        self.stacked_widget.addWidget(cards_widget)           # Index 5
        content_layout.addWidget(self.stacked_widget)
        self.passwords_button.clicked.connect(lambda: self.switch_page(0))
        self.add_button.clicked.connect(lambda: self.switch_page(1))
        self.notes_button.clicked.connect(lambda: self.switch_page(2))
        self.cards_button.clicked.connect(lambda: self.switch_page(5))
        self.settings_button.clicked.connect(lambda: self.switch_page(3))
        self.backup_button.clicked.connect(lambda: self.switch_page(4))
        main_layout.addWidget(sidebar)
        main_layout.addWidget(content_area)
        self.load_passwords()
        self.load_notes()
        self.load_cards()
        self.auto_lock_timeout = config.get("auto_lock_timeout", 45)
        if self.inactivity_timer is None:
            self.inactivity_timer = QTimer(self)
            self.inactivity_timer.timeout.connect(self.auto_lock)
        self.inactivity_timer.start(self.auto_lock_timeout * 1000)
        self.update_completers()

    def switch_page(self, index):
        self.stacked_widget.setCurrentIndex(index)
        self.passwords_button.setChecked(index == 0)
        self.add_button.setChecked(index == 1)
        self.notes_button.setChecked(index == 2)
        self.cards_button.setChecked(index == 5)
        self.settings_button.setChecked(index == 3)
        self.backup_button.setChecked(index == 4)

    def save_settings(self):
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            config["auto_lock_timeout"] = self.autolock_spinbox.value()
            with open(self.config_file, 'w') as f:
                json.dump(config, f)
            self.auto_lock_timeout = config["auto_lock_timeout"]
            if self.inactivity_timer is not None:
                self.inactivity_timer.setInterval(self.auto_lock_timeout * 1000)
            self.show_message("Success", "Settings have been saved.", QMessageBox.Icon.Information)
        except Exception as e:
            self.show_message("Error", f"Error saving settings: {str(e)}", QMessageBox.Icon.Critical)

    def disable_two_factor(self):
        confirm = QMessageBox.question(
            self,
            "Disable 2FA",
            "Are you sure you want to disable two-factor authentication?\n\nThis will reduce the security of your password manager.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            password, ok = QInputDialog.getText(
                self,
                "Confirmation Required",
                "Please enter your master password to confirm the change:",
                QLineEdit.EchoMode.Password
            )
            if ok and password:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                stored_hash = base64.b64decode(config["password_hash"])
                salt = base64.b64decode(config["salt"])
                password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
                if password_hash == stored_hash:
                    config["is_two_factor_enabled"] = False
                    config["secret_token"] = None
                    with open(self.config_file, 'w') as f:
                        json.dump(config, f)
                    self.show_message("Success", "Two-factor authentication has been disabled.", QMessageBox.Icon.Information)
                    self.show_dashboard()
                else:
                    self.show_message("Error", "Incorrect master password!", QMessageBox.Icon.Critical)

    def load_passwords(self):
        self.tree.clear()
        passwords = self.get_passwords()
        filter_text = self.filter_line_edit.text().lower().strip() if hasattr(self, "filter_line_edit") else ""
        for id, data in passwords.items():
            if filter_text in data.get("title", "").lower() or filter_text in data.get("username", "").lower() or filter_text == "":
                item = QTreeWidgetItem([data["title"], data["username"]])
                item.setData(0, Qt.ItemDataRole.UserRole, id)
                self.tree.addTopLevelItem(item)

    def save_passwords(self, passwords):
        try:
            data = json.dumps(passwords)
            cipher = Fernet(self.key)
            encrypted_data = cipher.encrypt(data.encode('utf-8'))
            with open(self.password_file, 'w') as f:
                f.write(encrypted_data.decode('utf-8'))
        except Exception as e:
            self.show_message("Error", f"Error saving passwords: {str(e)}", QMessageBox.Icon.Critical)

    def get_passwords(self):
        if not os.path.exists(self.password_file):
            return {}
        try:
            with open(self.password_file, 'r') as f:
                encrypted_data = f.read().strip()
            if not encrypted_data:
                return {}
            cipher = Fernet(self.key)
            decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8'))
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            return {}

    def get_notes(self):
        if not os.path.exists(self.notes_file):
            return {}
        try:
            with open(self.notes_file, 'r') as f:
                encrypted_data = f.read().strip()
            if not encrypted_data:
                return {}
            cipher = Fernet(self.key)
            decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8'))
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            return {}

    def save_notes(self, notes):
        try:
            data = json.dumps(notes)
            cipher = Fernet(self.key)
            encrypted_data = cipher.encrypt(data.encode('utf-8'))
            with open(self.notes_file, 'w') as f:
                f.write(encrypted_data.decode('utf-8'))
        except Exception as e:
            self.show_message("Error", f"Error saving notes: {str(e)}", QMessageBox.Icon.Critical)

    def load_notes(self):
        self.notes_tree.clear()
        notes = self.get_notes()
        filter_text = self.notes_filter_line_edit.text().lower().strip() if hasattr(self, "notes_filter_line_edit") else ""
        for note_id, data in notes.items():
            if filter_text in data.get("title", "Untitled").lower() or filter_text in data.get("content", "").lower() or filter_text == "":
                item = QTreeWidgetItem([data.get("title", "Untitled")])
                item.setData(0, Qt.ItemDataRole.UserRole, note_id)
                self.notes_tree.addTopLevelItem(item)

    def show_add_note_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Create New Note")
        dialog.setMinimumWidth(450)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(30, 30, 30, 30)
        title_label = ModernLabel("New Note", is_title=True)
        layout.addWidget(title_label)
        layout.addSpacing(20)
        form_layout = QFormLayout()
        title_entry = ModernLineEdit(placeholder="Note title")
        content_entry = QTextEdit()
        content_entry.setPlaceholderText("Note content")
        form_layout.addRow(ModernLabel("Title:"), title_entry)
        form_layout.addRow(ModernLabel("Content:"), content_entry)
        layout.addLayout(form_layout)
        layout.addSpacing(20)
        buttons_layout = QHBoxLayout()
        save_button = ModernButton("Save")
        cancel_button = ModernButton("Cancel", primary=False)
        buttons_layout.addStretch()
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(save_button)
        layout.addLayout(buttons_layout)
        cancel_button.clicked.connect(dialog.reject)
        save_button.clicked.connect(lambda: self.save_new_note(title_entry.text(), content_entry.toPlainText(), dialog))
        dialog.exec()

    def save_new_note(self, title, content, dialog):
        if not title and not content:
            self.show_message("Error", "Please enter a title or content!", QMessageBox.Icon.Critical)
            return
        note_id = secrets.token_hex(8)
        notes = self.get_notes()
        notes[note_id] = {"title": title, "content": content}
        self.save_notes(notes)
        dialog.accept()
        self.load_notes()
        self.show_message("Success", "Note saved successfully!", QMessageBox.Icon.Information)

    def view_note(self):
        selected_items = self.notes_tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select a note!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        note_id = item.data(0, Qt.ItemDataRole.UserRole)
        notes = self.get_notes()
        if note_id in notes:
            data = notes[note_id]
            dialog = QDialog(self)
            dialog.setWindowTitle("View Note")
            dialog.setMinimumWidth(450)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            title_label = ModernLabel("Note Details", is_title=True)
            layout.addWidget(title_label)
            layout.addSpacing(20)
            info_layout = QFormLayout()
            info_layout.addRow(ModernLabel("Title:"), ModernLabel(data.get("title", "")))
            info_layout.addRow(ModernLabel("Content:"), ModernLabel(data.get("content", "")))
            layout.addLayout(info_layout)
            layout.addSpacing(20)
            close_button = ModernButton("Close", primary=False)
            close_button.clicked.connect(dialog.accept)
            layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignRight)
            dialog.exec()

    def edit_note(self):
        selected_items = self.notes_tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select a note!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        note_id = item.data(0, Qt.ItemDataRole.UserRole)
        notes = self.get_notes()
        if note_id in notes:
            data = notes[note_id]
            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Note")
            dialog.setMinimumWidth(450)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            title_label = ModernLabel("Edit Note", is_title=True)
            layout.addWidget(title_label)
            layout.addSpacing(20)
            form_layout = QFormLayout()
            title_entry = ModernLineEdit()
            title_entry.setText(data.get("title", ""))
            content_entry = QTextEdit()
            content_entry.setPlainText(data.get("content", ""))
            form_layout.addRow(ModernLabel("Title:"), title_entry)
            form_layout.addRow(ModernLabel("Content:"), content_entry)
            layout.addLayout(form_layout)
            layout.addSpacing(20)
            buttons_layout = QHBoxLayout()
            save_button = ModernButton("Save")
            buttons_layout.addStretch()
            buttons_layout.addWidget(save_button)
            layout.addLayout(buttons_layout)
            save_button.clicked.connect(lambda: self.update_note(note_id, title_entry.text(), content_entry.toPlainText(), dialog))
            dialog.exec()

    def update_note(self, note_id, title, content, dialog):
        if not title and not content:
            self.show_message("Error", "Please enter a title or content!", QMessageBox.Icon.Critical)
            return
        notes = self.get_notes()
        notes[note_id] = {"title": title, "content": content}
        self.save_notes(notes)
        dialog.accept()
        self.load_notes()
        self.show_message("Success", "Note updated successfully!", QMessageBox.Icon.Information)

    def delete_note(self):
        selected_items = self.notes_tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select a note!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        note_id = item.data(0, Qt.ItemDataRole.UserRole)
        confirm = QMessageBox.question(
            self,
            "Delete Note",
            "Do you really want to delete this note?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            notes = self.get_notes()
            if note_id in notes:
                del notes[note_id]
                self.save_notes(notes)
                self.load_notes()
                self.show_message("Success", "Note deleted successfully!", QMessageBox.Icon.Information)

    def get_cards(self):
        if not os.path.exists(self.cards_file):
            return {}
        try:
            with open(self.cards_file, 'r') as f:
                encrypted_data = f.read().strip()
            if not encrypted_data:
                return {}
            cipher = Fernet(self.key)
            decrypted_data = cipher.decrypt(encrypted_data.encode('utf-8'))
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            return {}

    def save_cards(self, cards):
        try:
            data = json.dumps(cards)
            cipher = Fernet(self.key)
            encrypted_data = cipher.encrypt(data.encode('utf-8'))
            with open(self.cards_file, 'w') as f:
                f.write(encrypted_data.decode('utf-8'))
        except Exception as e:
            self.show_message("Error", f"Error saving cards: {str(e)}", QMessageBox.Icon.Critical)

    def load_cards(self):
        self.cards_tree.clear()
        cards = self.get_cards()
        filter_text = self.cards_filter_line_edit.text().lower().strip() if hasattr(self, "cards_filter_line_edit") else ""
        for card_id, data in cards.items():
            card_holder = data.get("card_holder", "")
            card_number = data.get("card_number", "")
            masked_number = "**** **** **** " + card_number[-4:] if len(card_number) >= 4 else card_number
            # Filter by cardholder or card number
            if filter_text in card_holder.lower() or filter_text in card_number:
                item = QTreeWidgetItem([card_holder, masked_number])
                item.setData(0, Qt.ItemDataRole.UserRole, card_id)
                self.cards_tree.addTopLevelItem(item)

    def show_add_card_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add New Card")
        dialog.setMinimumWidth(450)
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(30, 30, 30, 30)
        title_label = ModernLabel("Card Information", is_title=True)
        layout.addWidget(title_label)
        layout.addSpacing(20)
        form_layout = QFormLayout()
        card_holder_entry = ModernLineEdit(placeholder="Cardholder")
        card_number_entry = ModernLineEdit(placeholder="Card Number")
        expiry_entry = ModernLineEdit(placeholder="Expiry Date (MM/YY)")
        cvv_entry = ModernLineEdit(placeholder="CVV")
        cvv_entry.setEchoMode(QLineEdit.EchoMode.Password)
        form_layout.addRow(card_holder_entry)
        form_layout.addRow(card_number_entry)
        form_layout.addRow(expiry_entry)
        form_layout.addRow(cvv_entry)
        layout.addLayout(form_layout)
        layout.addSpacing(20)
        buttons_layout = QHBoxLayout()
        save_button = ModernButton("Save Card")
        cancel_button = ModernButton("Cancel", primary=False)
        buttons_layout.addStretch()
        buttons_layout.addWidget(cancel_button)
        buttons_layout.addWidget(save_button)
        layout.addLayout(buttons_layout)
        cancel_button.clicked.connect(dialog.reject)
        save_button.clicked.connect(lambda: self.save_new_card(card_holder_entry.text(), card_number_entry.text(), expiry_entry.text(), cvv_entry.text(), dialog))
        dialog.exec()

    def save_new_card(self, card_holder, card_number, expiry_date, cvv, dialog):
        if not card_holder or not card_number or not expiry_date:
            self.show_message("Error", "Please fill in all required fields!", QMessageBox.Icon.Critical)
            return
        card_id = secrets.token_hex(8)
        cards = self.get_cards()
        cards[card_id] = {
            "card_holder": card_holder,
            "card_number": card_number,
            "expiry_date": expiry_date,
            "cvv": cvv
        }
        self.save_cards(cards)
        dialog.accept()
        self.load_cards()
        self.show_message("Success", "Card saved successfully!", QMessageBox.Icon.Information)

    def view_card(self):
        selected_items = self.cards_tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select a card!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        card_id = item.data(0, Qt.ItemDataRole.UserRole)
        cards = self.get_cards()
        if card_id in cards:
            data = cards[card_id]
            dialog = QDialog(self)
            dialog.setWindowTitle("View Card")
            dialog.setMinimumWidth(500)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            # Use the custom CreditCardWidget
            card_widget = CreditCardWidget(
                data.get("card_holder", ""),
                data.get("card_number", ""),
                data.get("expiry_date", "")
            )
            layout.addWidget(card_widget)
            layout.addSpacing(20)
            close_button = ModernButton("Close", primary=False)
            close_button.clicked.connect(dialog.accept)
            layout.addWidget(close_button, alignment=Qt.AlignmentFlag.AlignRight)
            dialog.exec()

    def edit_card(self):
        selected_items = self.cards_tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select a card!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        card_id = item.data(0, Qt.ItemDataRole.UserRole)
        cards = self.get_cards()
        if card_id in cards:
            data = cards[card_id]
            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Card")
            dialog.setMinimumWidth(450)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            title_label = ModernLabel("Edit Card", is_title=True)
            layout.addWidget(title_label)
            layout.addSpacing(20)
            form_layout = QFormLayout()
            card_holder_entry = ModernLineEdit()
            card_holder_entry.setText(data.get("card_holder", ""))
            card_number_entry = ModernLineEdit()
            card_number_entry.setText(data.get("card_number", ""))
            expiry_entry = ModernLineEdit()
            expiry_entry.setText(data.get("expiry_date", ""))
            cvv_entry = ModernLineEdit()
            cvv_entry.setText(data.get("cvv", ""))
            cvv_entry.setEchoMode(QLineEdit.EchoMode.Password)
            form_layout.addRow(card_holder_entry)
            form_layout.addRow(card_number_entry)
            form_layout.addRow(expiry_entry)
            form_layout.addRow(cvv_entry)
            layout.addLayout(form_layout)
            layout.addSpacing(20)
            buttons_layout = QHBoxLayout()
            save_button = ModernButton("Save")
            buttons_layout.addStretch()
            buttons_layout.addWidget(save_button)
            layout.addLayout(buttons_layout)
            save_button.clicked.connect(lambda: self.update_card(card_id, card_holder_entry.text(), card_number_entry.text(), expiry_entry.text(), cvv_entry.text(), dialog))
            dialog.exec()

    def update_card(self, card_id, card_holder, card_number, expiry_date, cvv, dialog):
        if not card_holder or not card_number or not expiry_date:
            self.show_message("Error", "Please fill in all required fields!", QMessageBox.Icon.Critical)
            return
        cards = self.get_cards()
        cards[card_id] = {
            "card_holder": card_holder,
            "card_number": card_number,
            "expiry_date": expiry_date,
            "cvv": cvv
        }
        self.save_cards(cards)
        dialog.accept()
        self.load_cards()
        self.show_message("Success", "Card updated successfully!", QMessageBox.Icon.Information)

    def delete_card(self):
        selected_items = self.cards_tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select a card!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        card_id = item.data(0, Qt.ItemDataRole.UserRole)
        confirm = QMessageBox.question(
            self,
            "Delete Card",
            "Do you really want to delete this card?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            cards = self.get_cards()
            if card_id in cards:
                del cards[card_id]
                self.save_cards(cards)
                self.load_cards()
                self.show_message("Success", "Card deleted successfully!", QMessageBox.Icon.Information)

    def generate_and_set_password(self):
        password = self.generate_password()
        self.password_entry.setText(password)

    def generate_password(self, length=32):
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def save_new_password(self):
        title = self.title_entry.text()
        username = self.username_entry.text()
        password = self.password_entry.text()
        if not title or not username or not password:
            self.show_message("Error", "Please fill in all fields!", QMessageBox.Icon.Critical)
            return
        password_id = secrets.token_hex(8)
        passwords = self.get_passwords()
        passwords[password_id] = {"title": title, "username": username, "password": password}
        self.save_passwords(passwords)
        self.title_entry.clear()
        self.username_entry.clear()
        self.password_entry.clear()
        self.load_passwords()
        self.update_completers()
        self.show_message("Success", "Password saved successfully!", QMessageBox.Icon.Information)

    def view_password(self):
        selected_items = self.tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select an entry!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        password_id = item.data(0, Qt.ItemDataRole.UserRole)
        passwords = self.get_passwords()
        if password_id in passwords:
            data = passwords[password_id]
            dialog = QDialog(self)
            dialog.setWindowTitle("View Password")
            dialog.setMinimumWidth(450)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            title_label = ModernLabel("Password Details", is_title=True)
            layout.addWidget(title_label)
            layout.addSpacing(20)
            info_layout = QFormLayout()
            info_layout.addRow(ModernLabel("Title:"), ModernLabel(data["title"]))
            info_layout.addRow(ModernLabel("Username:"), ModernLabel(data["username"]))
            password_layout = QHBoxLayout()
            password_field = ModernLineEdit()
            password_field.setText(data["password"])
            password_field.setEchoMode(QLineEdit.EchoMode.Password)
            password_field.setReadOnly(True)
            show_button = QCheckBox("Show")
            show_button.toggled.connect(lambda checked: password_field.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password))
            password_layout.addWidget(password_field)
            password_layout.addWidget(show_button)
            info_layout.addRow(ModernLabel("Password:"), password_layout)
            layout.addLayout(info_layout)
            layout.addSpacing(20)
            buttons_layout = QHBoxLayout()
            copy_button = ModernButton("Copy Password")
            copy_button.clicked.connect(lambda: self.copy_to_clipboard(data["password"]))
            close_button = ModernButton("Close", primary=False)
            close_button.clicked.connect(dialog.accept)
            buttons_layout.addWidget(copy_button)
            buttons_layout.addStretch()
            buttons_layout.addWidget(close_button)
            layout.addLayout(buttons_layout)
            dialog.exec()

    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        self.show_message("Copied", "Password copied to clipboard.", QMessageBox.Icon.Information)

    def edit_password(self):
        selected_items = self.tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select an entry!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        password_id = item.data(0, Qt.ItemDataRole.UserRole)
        passwords = self.get_passwords()
        if password_id in passwords:
            data = passwords[password_id]
            dialog = QDialog(self)
            dialog.setWindowTitle("Edit Password")
            dialog.setMinimumWidth(450)
            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(30, 30, 30, 30)
            title_label = ModernLabel("Edit Password", is_title=True)
            layout.addWidget(title_label)
            layout.addSpacing(20)
            form_widget = QWidget()
            form_widget.setObjectName("formContainer")
            form_layout = QFormLayout(form_widget)
            form_layout.setSpacing(15)
            title_entry = ModernLineEdit()
            title_entry.setText(data["title"])
            username_entry = ModernLineEdit()
            username_entry.setText(data["username"])
            password_entry = ModernLineEdit()
            password_entry.setText(data["password"])
            password_entry.setEchoMode(QLineEdit.EchoMode.Password)
            password_layout = QHBoxLayout()
            password_layout.addWidget(password_entry)
            show_password = QCheckBox("Show")
            show_password.toggled.connect(lambda checked: password_entry.setEchoMode(QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password))
            password_layout.addWidget(show_password)
            form_layout.addRow(title_entry)
            form_layout.addRow(username_entry)
            form_layout.addRow(password_layout)
            layout.addWidget(form_widget)
            layout.addSpacing(20)
            buttons_layout = QHBoxLayout()
            generate_button = ModernButton("Generate Password", primary=False)
            generate_button.clicked.connect(lambda: password_entry.setText(self.generate_password()))
            save_button = ModernButton("Save")
            save_button.clicked.connect(lambda: self.update_password(password_id, title_entry.text(), username_entry.text(), password_entry.text(), dialog))
            buttons_layout.addWidget(generate_button)
            buttons_layout.addStretch()
            buttons_layout.addWidget(save_button)
            layout.addLayout(buttons_layout)
            dialog.exec()

    def update_password(self, password_id, title, username, password, dialog):
        if not title or not username or not password:
            self.show_message("Error", "Please fill in all fields!", QMessageBox.Icon.Critical)
            return
        passwords = self.get_passwords()
        passwords[password_id] = {"title": title, "username": username, "password": password}
        self.save_passwords(passwords)
        dialog.accept()
        self.load_passwords()
        self.update_completers()
        self.show_message("Success", "Password updated successfully!", QMessageBox.Icon.Information)

    def delete_password(self):
        selected_items = self.tree.selectedItems()
        if not selected_items:
            self.show_message("Error", "Please select an entry!", QMessageBox.Icon.Critical)
            return
        item = selected_items[0]
        password_id = item.data(0, Qt.ItemDataRole.UserRole)
        confirm = QMessageBox.question(self, "Confirm Deletion", "Do you really want to delete this password entry?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if confirm == QMessageBox.StandardButton.Yes:
            passwords = self.get_passwords()
            if password_id in passwords:
                del passwords[password_id]
                self.save_passwords(passwords)
                self.load_passwords()
                self.update_completers()
                self.show_message("Success", "Password deleted successfully!", QMessageBox.Icon.Information)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    try:
        with open(resource_path("dark.qss"), 'r') as f:
            app.setStyleSheet(f.read())
    except Exception as e:
        print(f"Error loading dark theme: {e}")
    window = PasswordManager()
    window.show()
    sys.exit(app.exec())