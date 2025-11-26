import sys
from typing import Optional

from PySide6.QtCore import Signal
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
            "Manage your encrypted files locally. Upload stores a file in your vault; "
            "Download restores one (by name or ID) into your downloads folder."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.files_label = QLabel("No files uploaded yet.")
        self.files_label.setWordWrap(True)
        self.files_label.setStyleSheet("font-family: monospace;")
        layout.addWidget(self.files_label)

        upload_btn = QPushButton("Upload file…")
        download_btn = QPushButton("Download file…")
        layout.addWidget(upload_btn)
        layout.addWidget(download_btn)
        layout.addStretch()

        upload_btn.clicked.connect(self._handle_upload)
        download_btn.clicked.connect(self._handle_download)

    def set_user(self, user: User) -> None:
        self._user = user
        self.welcome.setText(f"Welcome, {user.username}!")
        self._reload_files()

    def clear_user(self) -> None:
        self._user = None
        self.welcome.setText("")
        self.files_label.setText("No user logged in.")

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
        try:
            entry = upload_file(
                user.username,
                filepath,
                user_public_key_pem=self.accounts.public_key_pem(user),
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Upload failed", str(exc))
            return
        self._reload_files()
        QMessageBox.information(
            self,
            "Uploaded",
            f"Stored {entry.filename}\nID: {entry.file_id}",
        )

    def _handle_download(self) -> None:
        user = self._require_user()
        if not user:
            return
        filename, ok = QInputDialog.getText(self, "Download file", "Enter filename to download:")
        if not ok or not filename:
            return
        password, ok = QInputDialog.getText(
            self,
            "Password required",
            "Enter your password to decrypt:",
            QLineEdit.Password,
        )
        if not ok or password is None:
            return
        try:
            priv_key = self.accounts.decrypt_private_key(user, password)
            target = download_file(user.username, filename, private_key_pem=priv_key)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Download failed", str(exc))
            return
        QMessageBox.information(
            self,
            "Download complete",
            f"Saved to {target}",
        )
    
    def _reload_files(self) -> None:
        if not self._user:
            self.files_label.setText("No user logged in.")
            return
        entries = list_files(self._user.username)
        if not entries:
            self.files_label.setText("No files uploaded yet.")
            return
        lines = [f"{e.filename}  (id={e.file_id}, {e.size} bytes)" for e in entries]
        self.files_label.setText("\n".join(lines))



class MainWindow(QMainWindow):
    def __init__(self, accounts: AccountManager):
        super().__init__()
        self.setWindowTitle("Encrypted File Storage")
        self.resize(420, 320)

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
