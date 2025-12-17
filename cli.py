"""
Command-line interface for Encrypted File Storage.

Provides text-based menu for:
- User registration and login
- File upload with encryption and signing
- File download with decryption and signature verification
- File sharing between users
- File listing
"""

from getpass import getpass
from pathlib import Path

from accounts.storage import JSONStorage
from accounts.manager import AccountManager
from accounts.hashing import SimpleHasher
from accounts.models import User
from storage.file_manager import (
    upload_file, 
    download_file, 
    list_files, 
    share_file,
    list_shared_files,
    delete_file,
)


def create_account_manager() -> AccountManager:
    storage = JSONStorage("users.json")
    hasher = SimpleHasher()
    return AccountManager(storage, hasher)


def print_menu(logged_in: bool = False, username: str = "") -> None:
    print("\n" + "=" * 50)
    if logged_in:
        print(f"  🔐 Encrypted File Storage - Logged in as: {username}")
    else:
        print("  🔐 Encrypted File Storage")
    print("=" * 50)
    
    if not logged_in:
        print("  1) Sign up")
        print("  2) Log in")
        print("  0) Quit")
    else:
        print("  1) Upload file")
        print("  2) Download file")
        print("  3) List my files")
        print("  4) List shared files")
        print("  5) Share a file")
        print("  6) Delete a file")
        print("  7) Log out")
        print("  0) Quit")
    print("=" * 50)


def handle_signup(accounts: AccountManager) -> None:
    print("\n📝 Create New Account")
    username = input("Username: ").strip()
    if not username:
        print("❌ Username cannot be empty")
        return
    
    password = getpass("Password: ")
    if len(password) < 6:
        print("❌ Password must be at least 6 characters")
        return
    
    confirm = getpass("Confirm password: ")
    if password != confirm:
        print("❌ Passwords don't match")
        return
    
    try:
        user = accounts.register(username, password)
        print(f"✅ Account created: {user.username}")
        print(f"   User ID: {user.user_id}")
        print(f"   RSA key pair generated and securely stored")
    except ValueError as e:
        print(f"❌ Error: {e}")


def handle_login(accounts: AccountManager) -> tuple[User | None, str | None]:
    print("\n🔑 Login")
    username = input("Username: ").strip()
    password = getpass("Password: ")
    
    user = accounts.authenticate(username, password)
    if user:
        print(f"✅ Welcome back, {user.username}!")
        return user, password
    else:
        print("❌ Invalid credentials")
        return None, None


def handle_upload(accounts: AccountManager, user: User, password: str) -> None:
    print("\n📤 Upload File")
    filepath = input("File path: ").strip()
    
    if not filepath:
        print("❌ File path cannot be empty")
        return
    
    path = Path(filepath).expanduser()
    if not path.is_file():
        print(f"❌ File not found: {filepath}")
        return
    
    # Ask about sharing
    other_users = accounts.get_other_users(user.username)
    share_with_keys = {}
    
    if other_users:
        print(f"\nAvailable users to share with: {', '.join(u.username for u in other_users)}")
        share_input = input("Share with (comma-separated usernames, or press Enter to skip): ").strip()
        
        if share_input:
            share_usernames = [u.strip() for u in share_input.split(",")]
            share_with_keys = accounts.get_public_keys_for_users(share_usernames)
            if share_with_keys:
                print(f"   Will share with: {', '.join(share_with_keys.keys())}")
    
    try:
        priv_key = accounts.decrypt_private_key(user, password)
        entry = upload_file(
            user.username,
            filepath,
            user_public_key_pem=accounts.public_key_pem(user),
            user_private_key_pem=priv_key,
            share_with_public_keys=share_with_keys,
        )
        print(f"\n✅ File uploaded successfully!")
        print(f"   📄 Filename: {entry.filename}")
        print(f"   🔑 File ID: {entry.file_id}")
        print(f"   📊 Size: {entry.size:,} bytes")
        print(f"   🔒 Encrypted with AES-256-GCM")
        print(f"   ✍️ Digitally signed with RSA-PSS")
        if share_with_keys:
            print(f"   🔗 Shared with: {', '.join(share_with_keys.keys())}")
    except Exception as e:
        print(f"❌ Upload failed: {e}")


def handle_download(accounts: AccountManager, user: User, password: str) -> None:
    print("\n📥 Download File")
    
    # List files first
    files = list_files(user.username)
    shared = list_shared_files(user.username)
    
    all_files = files + shared
    if not all_files:
        print("   No files available")
        return
    
    print("\nYour files:")
    for i, f in enumerate(files, 1):
        sig = "✍️" if f.signature else ""
        print(f"   {i}. {f.filename} {sig} ({f.size:,} bytes)")
    
    if shared:
        print("\nShared with you:")
        for i, f in enumerate(shared, len(files) + 1):
            sig = "✍️" if f.signature else ""
            print(f"   {i}. {f.filename} {sig} (from {f.owner})")
    
    try:
        choice = int(input("\nSelect file number: ")) - 1
        if choice < 0 or choice >= len(all_files):
            print("❌ Invalid selection")
            return
        selected = all_files[choice]
    except ValueError:
        print("❌ Invalid input")
        return
    
    try:
        priv_key = accounts.decrypt_private_key(user, password)
        
        # Get signer's public key for verification
        verify_key = None
        if selected.signature and selected.signer:
            signer = accounts.get_user_by_username(selected.signer)
            if signer:
                verify_key = accounts.public_key_pem(signer)
        
        target, sig_valid, sig_msg = download_file(
            user.username,
            selected.filename,
            private_key_pem=priv_key,
            verify_signature_with_public_key=verify_key,
        )
        
        print(f"\n✅ File downloaded successfully!")
        print(f"   📁 Saved to: {target}")
        if sig_msg:
            if sig_valid:
                print(f"   ✅ {sig_msg}")
            elif sig_valid is False:
                print(f"   ⚠️ {sig_msg}")
            else:
                print(f"   ℹ️ {sig_msg}")
    except Exception as e:
        print(f"❌ Download failed: {e}")


def handle_list_files(user: User) -> None:
    print("\n📁 My Files")
    files = list_files(user.username)
    
    if not files:
        print("   No files uploaded yet")
        return
    
    for f in files:
        sig = "✍️" if f.signature else ""
        shared = f"🔗{len(f.shared_with)}" if f.shared_with else ""
        print(f"   • {f.filename} {sig}{shared}")
        print(f"     ID: {f.file_id[:8]}... | Size: {f.size:,} bytes | {f.created_at[:10]}")


def handle_list_shared(user: User) -> None:
    print("\n📥 Files Shared With Me")
    shared = list_shared_files(user.username)
    
    if not shared:
        print("   No files shared with you")
        return
    
    for f in shared:
        sig = "✍️" if f.signature else ""
        print(f"   • {f.filename} {sig} (from {f.owner})")
        print(f"     Size: {f.size:,} bytes | {f.created_at[:10]}")


def handle_share(accounts: AccountManager, user: User, password: str) -> None:
    print("\n🔗 Share a File")
    
    files = list_files(user.username)
    if not files:
        print("   No files to share")
        return
    
    print("\nYour files:")
    for i, f in enumerate(files, 1):
        shared_info = f" (shared with: {', '.join(f.shared_with)})" if f.shared_with else ""
        print(f"   {i}. {f.filename}{shared_info}")
    
    try:
        choice = int(input("\nSelect file to share: ")) - 1
        if choice < 0 or choice >= len(files):
            print("❌ Invalid selection")
            return
        selected = files[choice]
    except ValueError:
        print("❌ Invalid input")
        return
    
    # Get available users to share with
    other_users = accounts.get_other_users(user.username)
    available = [u for u in other_users if u.username not in selected.shared_with]
    
    if not available:
        print("   File is already shared with all users")
        return
    
    print(f"\nAvailable users: {', '.join(u.username for u in available)}")
    share_username = input("Share with: ").strip()
    
    target_user = accounts.get_user_by_username(share_username)
    if not target_user:
        print(f"❌ User '{share_username}' not found")
        return
    
    try:
        priv_key = accounts.decrypt_private_key(user, password)
        share_file(
            user.username,
            selected.filename,
            share_username,
            accounts.public_key_pem(target_user),
            priv_key,
        )
        print(f"✅ File shared with {share_username}")
    except Exception as e:
        print(f"❌ Share failed: {e}")


def handle_delete(user: User) -> None:
    print("\n🗑️ Delete a File")
    
    files = list_files(user.username)
    if not files:
        print("   No files to delete")
        return
    
    print("\nYour files:")
    for i, f in enumerate(files, 1):
        print(f"   {i}. {f.filename} ({f.size:,} bytes)")
    
    try:
        choice = int(input("\nSelect file to delete: ")) - 1
        if choice < 0 or choice >= len(files):
            print("❌ Invalid selection")
            return
        selected = files[choice]
    except ValueError:
        print("❌ Invalid input")
        return
    
    confirm = input(f"Delete '{selected.filename}'? (yes/no): ").strip().lower()
    if confirm != "yes":
        print("   Cancelled")
        return
    
    try:
        delete_file(user.username, selected.filename)
        print(f"✅ File deleted")
    except Exception as e:
        print(f"❌ Delete failed: {e}")


def main():
    accounts = create_account_manager()
    current_user: User | None = None
    current_password: str | None = None

    print("\n🔐 Encrypted File Storage System")
    print("   Secure • Signed • Shareable\n")

    while True:
        print_menu(logged_in=current_user is not None, 
                  username=current_user.username if current_user else "")
        choice = input("> ").strip()
        
        if current_user is None:
            # Not logged in
            if choice == "1":
                handle_signup(accounts)
            elif choice == "2":
                current_user, current_password = handle_login(accounts)
            elif choice == "0":
                print("\nGoodbye! 👋")
                break
            else:
                print("❌ Invalid choice")
        else:
            # Logged in
            if choice == "1":
                handle_upload(accounts, current_user, current_password)
            elif choice == "2":
                handle_download(accounts, current_user, current_password)
            elif choice == "3":
                handle_list_files(current_user)
            elif choice == "4":
                handle_list_shared(current_user)
            elif choice == "5":
                handle_share(accounts, current_user, current_password)
            elif choice == "6":
                handle_delete(current_user)
            elif choice == "7":
                print(f"\n👋 Logged out from {current_user.username}")
                current_user = None
                current_password = None
            elif choice == "0":
                print("\nGoodbye! 👋")
                break
            else:
                print("❌ Invalid choice")


if __name__ == "__main__":
    main()
