from user_manager import UserManager

def main():
    user_manager = UserManager()

    while True:
        print("\n=== Secure File Storage App ===")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            username = input("Enter new username: ").strip()
            password = input("Enter new password: ").strip()
            user_manager.register(username, password)

        elif choice == "2":
            username = input("Username: ").strip()
            password = input("Password: ").strip()
            if user_manager.login(username, password):
                user_session(username)
        elif choice == "3":
            print("Exiting Secure File Storage App.")
            break
        else:
            print("Error: Invalid option. Try again.")


def user_session(username):
    print(f"\n✅ Welcome, {username}!")
    while True:
        print("\n--- User Menu ---")
        print("1. Upload file (disabled until Lab 4)")
        print("2. Download file (disabled until Lab 4)")
        print("3. Logout")

        choice = input("Choose an option: ").strip()
        if choice == "3":
            print("Logged out.")
            break
        elif choice in ["1", "2"]:
            print("Feature coming soon in later labs.")
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
