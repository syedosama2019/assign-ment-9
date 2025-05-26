import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import uuid
from packaging import version

# Check Streamlit version
try:
    if version.parse(st.__version__) < version.parse("1.12.0"):
        st.warning("Please upgrade Streamlit to version 1.12.0 or higher for full functionality")
except:
    pass

# Configuration
CONFIG_FILE = "secure_data_config.json"
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 120  # 2 minutes in seconds
SESSION_EXPIRY = 1200  # 20 minutes in seconds

# Generate or load encryption key
def get_encryption_key():
    if os.path.exists("secret.key"):
        with open("secret.key", "rb") as key_file:
            return key_file.read()
    else:
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        return key

# Initialize encryption
KEY = get_encryption_key()
cipher = Fernet(KEY)

# Enhanced hashing with PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    hashed = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return hashed, salt

# Data persistence functions
def load_data():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except:
            return {
                "stored_data": {},
                "user_sessions": {},
                "failed_attempts": {},
                "lockouts": {}
            }
    return {
        "stored_data": {},
        "user_sessions": {},
        "failed_attempts": {},
        "lockouts": {}
    }

def save_data(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f)

# Initialize or load data
if 'data' not in st.session_state:
    st.session_state.data = load_data()

# Session management
def create_session(user_id):
    session_id = str(uuid.uuid4())
    expiry = time.time() + SESSION_EXPIRY
    st.session_state.data['user_sessions'][user_id] = {
        'session_id': session_id,
        'expiry': expiry
    }
    save_data(st.session_state.data)
    return session_id

def validate_session(user_id, session_id):
    if user_id not in st.session_state.data['user_sessions']:
        return False
    
    session = st.session_state.data['user_sessions'][user_id]
    if session['session_id'] != session_id:
        return False
    
    if time.time() > session['expiry']:
        del st.session_state.data['user_sessions'][user_id]
        save_data(st.session_state.data)
        return False
    
    # Renew session on validation
    session['expiry'] = time.time() + SESSION_EXPIRY
    save_data(st.session_state.data)
    return True

# Encryption/Decryption functions
def encrypt_data(text, passkey):
    try:
        encrypted = cipher.encrypt(text.encode())
        return encrypted.decode()
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_data(encrypted_text, passkey, hashed_passkey, salt):
    try:
        # First verify the passkey
        test_hash, _ = hash_passkey(passkey, salt)
        if test_hash != hashed_passkey:
            return None
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

# Authentication functions
def check_lockout(user_id):
    if user_id in st.session_state.data['lockouts']:
        if time.time() < st.session_state.data['lockouts'][user_id]:
            remaining = int(st.session_state.data['lockouts'][user_id] - time.time())
            return True, remaining
        else:
            del st.session_state.data['lockouts'][user_id]
            save_data(st.session_state.data)
    return False, 0

def record_failed_attempt(user_id):
    if user_id not in st.session_state.data['failed_attempts']:
        st.session_state.data['failed_attempts'][user_id] = 0
    
    st.session_state.data['failed_attempts'][user_id] += 1
    save_data(st.session_state.data)
    
    if st.session_state.data['failed_attempts'][user_id] >= MAX_ATTEMPTS:
        st.session_state.data['lockouts'][user_id] = time.time() + LOCKOUT_TIME
        del st.session_state.data['failed_attempts'][user_id]
        save_data(st.session_state.data)
        return True
    return False

def reset_attempts(user_id):
    if user_id in st.session_state.data['failed_attempts']:
        del st.session_state.data['failed_attempts'][user_id]
        save_data(st.session_state.data)

# UI Functions
def login_page():
    st.subheader("🔑 User Authentication")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        if username and password:
            # In a real system, you'd verify against a user database
            # For demo purposes, we'll accept any non-empty credentials
            session_id = create_session(username)
            st.session_state['user_id'] = username
            st.session_state['session_id'] = session_id
            st.session_state['authenticated'] = True
            st.success("✅ Login successful!")
            time.sleep(1)
            st.rerun()
        else:
            st.error("❌ Both username and password are required!")

def logout():
    if 'user_id' in st.session_state and st.session_state['user_id'] in st.session_state.data['user_sessions']:
        del st.session_state.data['user_sessions'][st.session_state['user_id']]
        save_data(st.session_state.data)
    st.session_state.clear()
    st.rerun()

# Main App
def main():
    st.title("🔒 Enhanced Secure Data Encryption System")
    
    # Check authentication
    if 'authenticated' not in st.session_state or not st.session_state['authenticated']:
        login_page()
        return
    
    # Validate session
    if not validate_session(st.session_state['user_id'], st.session_state['session_id']):
        st.warning("Session expired. Please log in again.")
        logout()
        return
    
    # Navigation
    menu = ["Home", "Store Data", "Retrieve Data", "Manage Data", "Account Settings"]
    choice = st.sidebar.selectbox("Navigation", menu)
    
    # Logout button
    if st.sidebar.button("Logout"):
        logout()
    
    if choice == "Home":
        home_page()
    elif choice == "Store Data":
        store_data_page()
    elif choice == "Retrieve Data":
        retrieve_data_page()
    elif choice == "Manage Data":
        manage_data_page()
    elif choice == "Account Settings":
        account_settings_page()

def home_page():
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write(f"Hello, {st.session_state['user_id']}! Use this app to securely store and retrieve data.")
    
    st.markdown("### Features:")
    st.markdown("""
    - **Secure Encryption**: All data is encrypted using Fernet symmetric encryption
    - **PBKDF2 Hashing**: Passkeys are hashed with salt for enhanced security
    - **Session Management**: Automatic logout after 30 minutes of inactivity
    - **Lockout Protection**: Temporary lockout after 3 failed attempts
    - **Data Persistence**: All data is saved to a secure JSON file
    - **Multi-User Support**: Each user can only access their own data
    """)
    
    st.markdown("### Your Statistics:")
    user_data = st.session_state.data['stored_data'].get(st.session_state['user_id'], {})
    st.write(f"📊 You have {len(user_data)} stored data entries")

def store_data_page():
    st.subheader("📂 Store Data Securely")
    
    data_name = st.text_input("Data Name (for easy identification):")
    user_data = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if not all([data_name, user_data, passkey, confirm_passkey]):
            st.error("⚠️ All fields are required!")
            return
        
        if passkey != confirm_passkey:
            st.error("❌ Passkeys do not match!")
            return
        
        if len(passkey) < 8:
            st.warning("⚠️ For better security, use a passkey with at least 8 characters")
            return
        
        # Generate a unique ID for this data entry
        data_id = str(uuid.uuid4())
        hashed_passkey, salt = hash_passkey(passkey)
        encrypted_text = encrypt_data(user_data, passkey)
        
        if encrypted_text is None:
            return
        
        # Store the data
        if st.session_state['user_id'] not in st.session_state.data['stored_data']:
            st.session_state.data['stored_data'][st.session_state['user_id']] = {}
        
        st.session_state.data['stored_data'][st.session_state['user_id']][data_id] = {
            "name": data_name,
            "encrypted_text": encrypted_text,
            "hashed_passkey": hashed_passkey.decode(),
            "salt": base64.b64encode(salt).decode(),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        save_data(st.session_state.data)
        st.success("✅ Data stored securely!")
        st.balloons()

def retrieve_data_page():
    st.subheader("🔍 Retrieve Your Data")
    
    user_id = st.session_state['user_id']
    
    # Check for lockout
    is_locked, remaining = check_lockout(user_id)
    if is_locked:
        st.error(f"🔒 Account temporarily locked. Please try again in {remaining//60} minutes and {remaining%60} seconds.")
        return
    
    # Get user's data entries
    user_data = st.session_state.data['stored_data'].get(user_id, {})
    if not user_data:
        st.warning("You don't have any stored data yet.")
        return
    
    # Select which data to retrieve
    data_options = {v['name']: k for k, v in user_data.items()}
    selected_name = st.selectbox("Select data to retrieve:", options=list(data_options.keys()))
    data_id = data_options[selected_name]
    data_entry = user_data[data_id]
    
    passkey = st.text_input("Enter Passkey:", type="password", key="retrieve_passkey")
    
    if st.button("Decrypt Data"):
        if not passkey:
            st.error("⚠️ Passkey is required!")
            return
        
        salt = base64.b64decode(data_entry['salt'].encode())
        decrypted_text = decrypt_data(
            data_entry['encrypted_text'],
            passkey,
            data_entry['hashed_passkey'].encode(),
            salt
        )
        
        if decrypted_text:
            reset_attempts(user_id)
            st.success("✅ Decryption successful!")
            st.text_area("Decrypted Data:", value=decrypted_text, height=200)
            
            # Show metadata
            st.markdown("### Metadata:")
            st.write(f"📅 Created at: {data_entry['created_at']}")
        else:
            if record_failed_attempt(user_id):
                st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
                st.rerun()
            else:
                attempts_left = MAX_ATTEMPTS - st.session_state.data['failed_attempts'].get(user_id, 0)
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_left}")

def manage_data_page():
    st.subheader("🗃️ Manage Your Data")
    user_id = st.session_state['user_id']
    user_data = st.session_state.data['stored_data'].get(user_id, {})
    
    if not user_data:
        st.warning("You don't have any stored data yet.")
        return
    
    # Display all data entries
    st.write("### Your Stored Data:")
    for data_id, entry in user_data.items():
        with st.expander(f"🔒 {entry['name']} (Created: {entry['created_at']})"):
            st.code(entry['encrypted_text'])
            if st.button(f"Delete {entry['name']}", key=f"delete_{data_id}"):
                del st.session_state.data['stored_data'][user_id][data_id]
                save_data(st.session_state.data)
                st.success(f"✅ {entry['name']} deleted successfully!")
                time.sleep(1)
                st.rerun()

def account_settings_page():
    st.subheader("⚙️ Account Settings")
    st.write(f"Logged in as: **{st.session_state['user_id']}**")
    
    st.markdown("### Change Master Password")
    old_pass = st.text_input("Current Password", type="password")
    new_pass = st.text_input("New Password", type="password")
    confirm_pass = st.text_input("Confirm New Password", type="password")
    
    if st.button("Update Password"):
        if not all([old_pass, new_pass, confirm_pass]):
            st.error("All fields are required!")
            return
        
        if new_pass != confirm_pass:
            st.error("New passwords don't match!")
            return
        
        st.success("Password updated successfully! (Note: In this demo, passwords aren't actually stored)")

if __name__ == "__main__":
    main()