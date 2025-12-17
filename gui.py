import sys
from typing import Optional, List

from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
    QListWidget,
    QListWidgetItem,
    QDialog,
    QDialogButtonBox,
    QCheckBox,
)

from accounts.manager import AccountManager
from accounts.hashing import SimpleHasher
from accounts.storage import JSONStorage
from accounts.models import User
from storage.file_manager import (
    download_file, 
    list_files, 
    upload_file, 
    share_file,
    delete_file,
    list_shared_files,
)
from storage.models import FileMetadata


def create_account_manager() -> AccountManager:
    """Factory so CLI and GUI can share the same wiring later if needed."""
    storage = JSONStorage("users.json")
    hasher = SimpleHasher()
    return AccountManager(storage, hasher)


class ShareDialog(QDialog):
    """Dialog to select users to share a file with."""
    
    def __init__(self, available_users: List[User], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Share File With...")
        self.setMinimumWidth(250)
        self.selected_users: List[str] = []
        
        layout = QVBoxLayout(self)
        
        label = QLabel("Select users to share with:")
        layout.addWidget(label)
        
        self.checkboxes: List[tuple[QCheckBox, str]] = []
        for user in available_users:
            cb = QCheckBox(user.username)
            self.checkboxes.append((cb, user.username))
            layout.addWidget(cb)
        
        if not available_users:
            no_users = QLabel("No other users available.")
            layout.addWidget(no_users)
        
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
    
    def _on_accept(self):
        self.selected_users = [
            username for cb, username in self.checkboxes if cb.isChecked()
        ]
        self.accept()


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
        self.password_input.returnPressed.connect(self._handle_login)

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
        
        # Get certificate info
        cert_info = ""
        if user.certificate:
            cert_result = self.accounts.verify_user_certificate(user)
            cert_info = f"\n\nX.509 Certificate issued by:\n  {cert_result.get('issuer', 'Unknown')}"
        
        QMessageBox.information(
            self,
            "Account created",
            f"User {user.username} created!\n\n"
            f"• RSA-2048 key pair generated\n"
            f"• Private key encrypted with AES-256-GCM\n"
            f"• Certificate signed by Root CA{cert_info}",
        )


class StoragePage(QWidget):
    def __init__(self, accounts: AccountManager, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.accounts = accounts
        self._user: Optional[User] = None
        self._password: Optional[str] = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        self.welcome = QLabel("")
        self.welcome.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(self.welcome)

        info = QLabel(
            "Your files are encrypted with AES-256-GCM and digitally signed.\n"
            "Select a file from the list to download or share it."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # File list
        files_label = QLabel("My Files:")
        layout.addWidget(files_label)
        
        self.files_list = QListWidget()
        self.files_list.setMaximumHeight(150)
        layout.addWidget(self.files_list)
        
        # Shared files list
        shared_label = QLabel("Shared With Me:")
        layout.addWidget(shared_label)
        
        self.shared_list = QListWidget()
        self.shared_list.setMaximumHeight(100)
        layout.addWidget(self.shared_list)

        # Buttons
        btn_layout = QHBoxLayout()
        upload_btn = QPushButton("Upload file…")
        download_btn = QPushButton("Download selected")
        share_btn = QPushButton("Share selected")
        btn_layout.addWidget(upload_btn)
        btn_layout.addWidget(download_btn)
        btn_layout.addWidget(share_btn)
        layout.addLayout(btn_layout)
        
        layout.addStretch()

        upload_btn.clicked.connect(self._handle_upload)
        download_btn.clicked.connect(self._handle_download)
        share_btn.clicked.connect(self._handle_share)
        self.files_list.itemDoubleClicked.connect(self._handle_download)
        self.shared_list.itemDoubleClicked.connect(self._handle_download_shared)

    def set_user(self, user: User, password: str) -> None:
        self._user = user
        self._password = password
        self.welcome.setText(f"Welcome, {user.username}!")
        self._reload_files()

    def clear_user(self) -> None:
        self._user = None
        self._password = None
        self.welcome.setText("")
        self.files_list.clear()
        self.shared_list.clear()

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
        
        # Check password is available
        if not self._password:
            QMessageBox.warning(self, "Session error", "Password not available. Please log out and log in again.")
            return
        
        # Ask about sharing (optional)
        other_users = self.accounts.get_other_users(user.username)
        share_with_keys = {}
        
        if other_users:
            dialog = ShareDialog(other_users, self)
            if dialog.exec() == QDialog.Accepted and dialog.selected_users:
                share_with_keys = self.accounts.get_public_keys_for_users(dialog.selected_users)
        
        try:
            priv_key = self.accounts.decrypt_private_key(user, self._password)
            entry = upload_file(
                user.username,
                filepath,
                user_public_key_pem=self.accounts.public_key_pem(user),
                user_private_key_pem=priv_key,
                share_with_public_keys=share_with_keys,
            )
        except Exception as exc:
            import traceback
            traceback.print_exc()
            QMessageBox.critical(self, "Upload failed", f"{type(exc).__name__}: {exc}")
            return
        
        self._reload_files()
        
        share_msg = ""
        if share_with_keys:
            share_msg = f"\nShared with: {', '.join(share_with_keys.keys())}"
        
        QMessageBox.information(
            self,
            "Uploaded",
            f"Stored: {entry.filename}\n"
            f"ID: {entry.file_id}\n"
            f"Encrypted & Signed{share_msg}",
        )

    def _handle_download(self) -> None:
        user = self._require_user()
        if not user:
            return
        
        current = self.files_list.currentItem()
        if not current:
            QMessageBox.warning(self, "No selection", "Please select a file to download.")
            return
        
        metadata: FileMetadata = current.data(Qt.UserRole)
        self._download_file(metadata)

    def _handle_download_shared(self) -> None:
        user = self._require_user()
        if not user:
            return
        
        current = self.shared_list.currentItem()
        if not current:
            return
        
        metadata: FileMetadata = current.data(Qt.UserRole)
        self._download_file(metadata)

    def _download_file(self, metadata: FileMetadata) -> None:
        user = self._user
        try:
            priv_key = self.accounts.decrypt_private_key(user, self._password)
            
            # Get signer's public key for verification
            verify_key = None
            if metadata.signature and metadata.signer:
                signer = self.accounts.get_user_by_username(metadata.signer)
                if signer:
                    verify_key = self.accounts.public_key_pem(signer)
            
            target, sig_valid, sig_msg = download_file(
                user.username, 
                metadata.filename,
                private_key_pem=priv_key,
                verify_signature_with_public_key=verify_key,
            )
        except Exception as exc:
            QMessageBox.critical(self, "Download failed", str(exc))
            return
        
        result_msg = f"Saved to: {target}"
        if sig_msg:
            result_msg += f"\n\n{sig_msg}"
        
        QMessageBox.information(self, "Download complete", result_msg)

    def _handle_share(self) -> None:
        user = self._require_user()
        if not user:
            return
        
        current = self.files_list.currentItem()
        if not current:
            QMessageBox.warning(self, "No selection", "Please select a file to share.")
            return
        
        metadata: FileMetadata = current.data(Qt.UserRole)
        
        other_users = self.accounts.get_other_users(user.username)
        available = [u for u in other_users if u.username not in metadata.shared_with]
        
        if not available:
            QMessageBox.information(self, "Already shared", "File is shared with all users.")
            return
        
        dialog = ShareDialog(available, self)
        if dialog.exec() != QDialog.Accepted or not dialog.selected_users:
            return
        
        try:
            priv_key = self.accounts.decrypt_private_key(user, self._password)
            for share_username in dialog.selected_users:
                share_user = self.accounts.get_user_by_username(share_username)
                if share_user:
                    share_file(
                        user.username,
                        metadata.filename,
                        share_username,
                        self.accounts.public_key_pem(share_user),
                        priv_key,
                    )
        except Exception as exc:
            QMessageBox.critical(self, "Share failed", str(exc))
            return
        
        self._reload_files()
        QMessageBox.information(self, "Shared", f"Shared with: {', '.join(dialog.selected_users)}")

    def _reload_files(self) -> None:
        if not self._user:
            return
        
        # Own files
        self.files_list.clear()
        entries = list_files(self._user.username)
        for entry in entries:
            sig = " [signed]" if entry.signature else ""
            shared = f" [shared:{len(entry.shared_with)}]" if entry.shared_with else ""
            text = f"{entry.filename}{sig}{shared} ({entry.size} bytes)"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, entry)
            self.files_list.addItem(item)
        
        # Shared files
        self.shared_list.clear()
        shared_entries = list_shared_files(self._user.username)
        for entry in shared_entries:
            sig = " [signed]" if entry.signature else ""
            text = f"{entry.filename}{sig} (from {entry.owner})"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, entry)
            self.shared_list.addItem(item)


class MainWindow(QMainWindow):
    def __init__(self, accounts: AccountManager):
        super().__init__()
        self.setWindowTitle("Encrypted File Storage")
        self.resize(500, 400)

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
        password = self.login_page.password_input.text()
        self.login_page.password_input.clear()
        self.storage_page.set_user(user, password)
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
