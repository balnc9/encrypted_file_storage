import sys
from typing import Optional

from PySide6.QtCore import Signal
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
    QInputDialog,
    QLineEdit,
)

from accounts.manager import AccountManager
from accounts.hashing import SimpleHasher
from accounts.storage import JSONStorage
from accounts.models import User
from storage.file_manager import download_file, list_files, upload_file


def create_account_manager() -> AccountManager:
    """Factory so CLI and GUI can share the same wiring later if needed."""
    storage = JSONStorage("users.json")
    hasher = SimpleHasher()
    return AccountManager(storage, hasher)


class LoginPage(QWidget):
    authenticated = Signal(object)  # emits a User instance

    def __init__(self, accounts: AccountManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.accounts = accounts
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        heading = QLabel("Login")
        heading.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 8px;")
        layout.addWidget(heading)

        form = QFormLayout()
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("alice")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("••••••••")
        self.password_input.setEchoMode(QLineEdit.Password)
        form.addRow("Username", self.username_input)
        form.addRow("Password", self.password_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.login_button = QPushButton("Log In")
        self.register_button = QPushButton("Sign Up")
        buttons.addWidget(self.login_button)
        buttons.addWidget(self.register_button)
        layout.addLayout(buttons)

        layout.addStretch()

        self.login_button.clicked.connect(self._handle_login)
        self.register_button.clicked.connect(self._handle_register)

    def _read_inputs(self) -> tuple[str, str]:
        return self.username_input.text().strip(), self.password_input.text()

    def _handle_login(self) -> None:
        username, password = self._read_inputs()
        if not username or not password:
            QMessageBox.warning(self, "Missing info", "Please fill in both username and password.")
            return

        user = self.accounts.authenticate(username, password)
        if not user:
            QMessageBox.warning(self, "Login failed", "Invalid credentials. Try again or sign up.")
            return

        self.password_input.clear()
        QMessageBox.information(self, "Welcome", f"Logged in as {user.username}")
        self.authenticated.emit(user)

    def _handle_register(self) -> None:
        username, password = self._read_inputs()
        if not username or not password:
            QMessageBox.warning(self, "Missing info", "Username and password are both required.")
            return
        try:
            user = self.accounts.register(username, password)
        except ValueError as exc:
            QMessageBox.warning(self, "Sign-up error", str(exc))
            return

        self.password_input.clear()
        QMessageBox.information(
            self,
            "Account created",
            f"User {user.username} created. You can log in now.",
        )


class StoragePage(QWidget):
    def __init__(self, accounts: AccountManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.accounts = accounts
        self._user: Optional[User] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        self.welcome = QLabel("")
        self.welcome.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(self.welcome)

        info = QLabel(
            "Manage your encrypted files. Click 'Upload File' to add a new file, "
            "or click the download button next to any file to retrieve it."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        upload_btn = QPushButton("Upload File")
        upload_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        upload_btn.clicked.connect(self._handle_upload)
        layout.addWidget(upload_btn)

        # Files section header
        files_header = QLabel("Your Files:")
        files_header.setStyleSheet("font-size: 14px; font-weight: bold; margin-top: 10px;")
        layout.addWidget(files_header)

        # Scrollable area for file list
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.StyledPanel)
        scroll_area.setStyleSheet("QScrollArea { background-color: white; }")
        
        self.files_container = QWidget()
        self.files_layout = QVBoxLayout(self.files_container)
        self.files_layout.setSpacing(8)
        
        self.empty_label = QLabel("No files uploaded yet.")
        self.empty_label.setStyleSheet("color: #555; padding: 20px; font-size: 13px;")
        self.files_layout.addWidget(self.empty_label)
        self.files_layout.addStretch()
        
        scroll_area.setWidget(self.files_container)
        layout.addWidget(scroll_area, 1)  # Give it stretch factor

    def set_user(self, user: User) -> None:
        self._user = user
        self.welcome.setText(f"Welcome, {user.username}!")
        self._reload_files()

    def clear_user(self) -> None:
        self._user = None
        self.welcome.setText("")
        self._clear_file_list()

    def _require_user(self) -> Optional[User]:
        if not self._user:
            QMessageBox.warning(self, "Not logged in", "Please log in first.")
        return self._user

    def _handle_upload(self) -> None:
        user = self._require_user()
        if not user:
            return
        filepath, _ = QFileDialog.getOpenFileName(self, "Select file to upload")
        if not filepath:
            return
        
        # Request password to decrypt private key for signing
        password, ok = QInputDialog.getText(
            self,
            "Password required",
            "Enter your password to sign the file:",
            QLineEdit.Password,
        )
        if not ok or password is None:
            return
        
        try:
            # Decrypt private key for signing
            priv_key = self.accounts.decrypt_private_key(user, password)
            
            # Get certificate for signature verification (handle legacy users)
            cert_pem = None
            has_signature = False
            if user.certificate:
                cert_pem = self.accounts.get_certificate_pem(user)
                has_signature = True
            
            entry = upload_file(
                user.username,
                filepath,
                user_public_key_pem=self.accounts.public_key_pem(user),
                private_key_pem=priv_key if has_signature else None,
                certificate_pem=cert_pem,
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Upload failed", str(exc))
            return
        self._reload_files()
        
        # Show appropriate message based on whether file was signed
        if has_signature:
            QMessageBox.information(
                self,
                "Uploaded & Signed",
                f"File encrypted and digitally signed!\n\n{entry.filename}\nID: {entry.file_id}",
            )
        else:
            QMessageBox.information(
                self,
                "Uploaded",
                f"File encrypted (no signature - legacy account).\n\n{entry.filename}\nID: {entry.file_id}\n\nNote: Re-register to enable digital signatures.",
            )

    def _handle_download(self, filename: str) -> None:
        user = self._require_user()
        if not user:
            return
        
        password, ok = QInputDialog.getText(
            self,
            "Password required",
            f"Enter your password to decrypt '{filename}':",
            QLineEdit.Password,
        )
        if not ok or password is None:
            return
        
        try:
            priv_key = self.accounts.decrypt_private_key(user, password)
            
            # Check if file has a signature (for appropriate messaging)
            from storage.file_manager import list_files
            entries = list_files(user.username)
            file_entry = next((e for e in entries if e.filename == filename or e.file_id == filename), None)
            has_signature = file_entry and file_entry.signature
            
            target = download_file(
                user.username, 
                filename, 
                private_key_pem=priv_key,
                check_signature=True  # Enable signature verification
            )
        except ValueError as exc:
            # Signature verification failures are ValueError
            QMessageBox.critical(
                self, 
                "Security Warning", 
                f"SIGNATURE VERIFICATION FAILED!\n\n{str(exc)}\n\n"
                "The file may have been tampered with!"
            )
            return
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Download failed", str(exc))
            return
        
        # Show appropriate message
        if has_signature:
            QMessageBox.information(
                self,
                "Download Complete",
                f"File decrypted and signature verified!\n\nSaved to:\n{target}",
            )
        else:
            QMessageBox.information(
                self,
                "Download Complete",
                f"File decrypted (no signature - legacy file).\n\nSaved to:\n{target}",
            )
    
    def _clear_file_list(self) -> None:
        """Remove all file widgets from the list."""
        while self.files_layout.count() > 0:
            item = self.files_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        self.empty_label = QLabel("No user logged in.")
        self.empty_label.setStyleSheet("color: #555; padding: 20px; font-size: 13px;")
        self.files_layout.addWidget(self.empty_label)
        self.files_layout.addStretch()
    
    def _reload_files(self) -> None:
        if not self._user:
            self._clear_file_list()
            return
        
        entries = list_files(self._user.username)
        
        # Clear existing widgets
        while self.files_layout.count() > 0:
            item = self.files_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        if not entries:
            self.empty_label = QLabel("No files uploaded yet. Click 'Upload File' to get started!")
            self.empty_label.setStyleSheet("color: #555; padding: 20px; font-size: 13px;")
            self.files_layout.addWidget(self.empty_label)
            self.files_layout.addStretch()
            return
        
        # Create a widget for each file
        for entry in entries:
            file_widget = QFrame()
            file_widget.setFrameShape(QFrame.Box)
            file_widget.setStyleSheet("""
                QFrame {
                    background-color: #e8e8e8;
                    border: 2px solid #bbb;
                    border-radius: 3px;
                }
            """)
            
            file_layout = QHBoxLayout(file_widget)
            file_layout.setContentsMargins(12, 10, 12, 10)
            
            # Format file size
            size_kb = entry.size / 1024
            if size_kb < 1024:
                size_str = f"{size_kb:.1f} KB"
            else:
                size_str = f"{size_kb / 1024:.1f} MB"
            
            # Simple file label
            file_label = QLabel(f"{entry.filename} ({size_str})")
            file_label.setStyleSheet("font-size: 14px; color: #000; font-weight: normal; background: transparent; border: none;")
            
            file_layout.addWidget(file_label, 1)
            
            # Download button
            download_btn = QPushButton("Download")
            download_btn.setStyleSheet("""
                QPushButton {
                    background-color: #2196F3;
                    color: white;
                    border: none;
                    padding: 6px 20px;
                    font-size: 13px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #1976D2;
                }
                QPushButton:pressed {
                    background-color: #0D47A1;
                }
            """)
            download_btn.clicked.connect(lambda checked=False, fn=entry.filename: self._handle_download(fn))
            
            file_layout.addWidget(download_btn)
            
            self.files_layout.addWidget(file_widget)
        
        self.files_layout.addStretch()



class MainWindow(QMainWindow):
    def __init__(self, accounts: AccountManager):
        super().__init__()
        self.setWindowTitle("Encrypted File Storage")
        self.resize(600, 500)

        self.accounts = accounts
        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.login_page = LoginPage(accounts)
        self.storage_page = StoragePage(accounts)

        self.stack.addWidget(self.login_page)
        self.stack.addWidget(self.storage_page)
        self.stack.setCurrentWidget(self.login_page)

        self.login_page.authenticated.connect(self._handle_authenticated)

        logout_action = QAction("Log out", self)
        logout_action.triggered.connect(self._show_login_again)
        self.logout_action = logout_action
        self.logout_action.setEnabled(False)

        account_menu = self.menuBar().addMenu("Account")
        account_menu.addAction(self.logout_action)

    def _handle_authenticated(self, user: User) -> None:
        self.storage_page.set_user(user)
        self.stack.setCurrentWidget(self.storage_page)
        self.logout_action.setEnabled(True)

    def _show_login_again(self) -> None:
        self.storage_page.clear_user()
        self.stack.setCurrentWidget(self.login_page)
        self.logout_action.setEnabled(False)


def main() -> int:
    app = QApplication(sys.argv)
    accounts = create_account_manager()
    window = MainWindow(accounts)
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
