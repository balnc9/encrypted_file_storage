import os
import binascii

class UserManager:
    def __init__(self):
        # In-memory user storage {username: password}
        # Will later move to JSON + hashed passwords
        self.users = {}

    def register(self, username, password):
        if username in self.users:
            print("Username already exists.")
            return False

        self.users[username] = password
        print(f"User '{username}' registered successfully.")
        return True

    def login(self, username, password):
        stored_pwd = self.users.get(username)
        if stored_pwd is None:
            print("User not found.")
            return False

        if stored_pwd == password:
            session_id = self._generate_session_id()
            print(f"Login successful! (Session ID: {session_id})")
            return True
        else:
            print("Incorrect password.")
            return False

    def _generate_session_id(self):
        # Generates random session ID (future: JWT or token)
        return binascii.hexlify(os.urandom(8)).decode()
