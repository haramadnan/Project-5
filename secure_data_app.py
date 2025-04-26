import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key (this would be constant in real apps)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Session State Setup
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {"encrypted_text": ..., "passkey": hashed}}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False

# Hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)

    entry = st.session_state.stored_data.get(encrypted_text)
    if entry and entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

# Navigation
st.title("🛡 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

# --------------------------- HOME ----------------------------
if choice == "Home":
    st.subheader("🤗 Welcome")
    st.write("Securely *store* and *retrieve* data with passkey encryption using Streamlit.")
    st.write(" 🔐🅒 Haram Adnan")
# --------------------------- STORE DATA ----------------------------
elif choice == "Store Data":
    st.subheader("📦 Store Data")
    user_text = st.text_area("Enter Data to Encrypt")
    user_pass = st.text_input("Enter a Passkey", type="password")

    if st.button("Encrypt & Store"):
        if user_text and user_pass:
            hashed = hash_passkey(user_pass)
            encrypted = encrypt_data(user_text)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data Encrypted and Stored!")
            st.code(encrypted, language='text')
        else:
            st.warning("Please enter both Data and Passkey.")

# --------------------------- RETRIEVE DATA ----------------------------
elif choice == "Retrieve Data":
    st.subheader("🗝️ Retrieve Encrypted Data")

    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🚫 Too many failed attempts! Please login to continue.")
        st.switch_page("Login")  # Optional: redirect with multipage setup
        st.stop()

    encrypted_input = st.text_area("Paste Encrypted Text:")
    passkey_input = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Data Decrypted Successfully:")
                st.code(result, language='text')
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect Passkey! Attempts left: {remaining}")
                if remaining <= 0:
                    st.warning("🔐 Too many failed attempts! Please reauthorize.")
        else:
            st.warning("Both fields are required.")

# --------------------------- LOGIN ----------------------------
elif choice == "Login":
    st.subheader("🔐 Reauthorize to Continue")
    master_key = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_key == "admin123":  # Set your master password
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Reauthorized! You may now access the Decryption page.")
        else:
            st.error("❌ Incorrect Master Password.")