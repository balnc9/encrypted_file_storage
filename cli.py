from getpass import getpass
from accounts.storage import JSONStorage
from accounts.manager import AccountManager
from accounts.hashing import SimpleHasher

def main():
    storage = JSONStorage("users.json")
    hasher = SimpleHasher()
    accounts = AccountManager(storage, hasher)

    while True:
        print("\n1) Sign up  2) Log in  0) Quit")
        choice = input("> ").strip()
        if choice == "1":
            u = input("Username: ")
            p = getpass("Password: ")
            try:
                user = accounts.register(u, p)
                print(f"Created {user.username} ({user.user_id})")
            except ValueError as e:
                print(f"Error: {e}")
        elif choice == "2":
            u = input("Username: ")
            p = getpass("Password: ")
            user = accounts.authenticate(u, p)
            print("✅ Login OK" if user else "❌ Invalid credentials")
        elif choice == "0":
            break

if __name__ == "__main__":
    main()
