import streamlit as st 
from cryptography.fernet import Fernet
import hashlib
import json
import os

KEY_FILE = "secret.key"
DATA_FILE = "secure_data.json"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        key = f.read()
        try:
            cipher_suite = Fernet(key)
        except ValueError:
            st.warning("⚠️ Invalid Key found, Generating a new key!")
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as f_new:
                f_new.write(key)
            cipher_suite = Fernet(key)

else: 
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    cipher_suite = Fernet(key)

if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        st.session_state.stored_data = json.load(f)

else:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'menu' not in st.session_state:
    st.session_state.menu = "Home"

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):

    encrypted = cipher_suite.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)

    st.session_state.stored_data[encrypted] = {
        "encrypted_text": encrypted,
        "passkey": hashed_passkey
    }

    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f, indent=4)

    return encrypted

def decrypt_data(encrypted_text, passkey):
    if encrypted_text not in st.session_state.stored_data:
        st.session_state.failed_attempts +=1
        return None
    
    stored_entry = st.session_state.stored_data[encrypted_text]
    hashed_passkey = hash_passkey(passkey)

    if stored_entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        try:
            return cipher_suite.decrypt(encrypted_text.encode()).decode()
        except:
            return None
    else:
        st.session_state.failed_attempts +=1
        return None
    
st.title("🔐 Data Encruption System")

if 'menu' not in st.session_state:
    st.session_state.menu = "Home"

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
menu_index = menu.index(st.session_state.menu)
choice = st.sidebar.selectbox("Navigation", menu, index=menu_index)

if choice != st.session_state.menu:
    st.session_state.menu = choice
    st.rerun()

if st.session_state.menu == "Home":
    st.subheader("🏡 Welcome to the Data Encryption System!")
    st.write("Use this app to **Securely store and Retrieve** your data using unique passkeys.")

elif st.session_state.menu == "Store Data":
    st.subheader("🔏 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data, passkey)
            st.success("Data Stored Securely ✅")
            st.text("Your encrypted data (Copy this for retrive your data):")
            st.code(encrypted)

        else:
            st.error("⚠️Please enter both data and passkey!")

elif st.session_state.menu == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Encrypted Data")
    encrypted_text = st.text_area("Enter Your Encrypted Data:")
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Retrieve"):
        if not encrypted_text or not passkey:
            st.error("⚠️Please Enter Both encrypted data and passkey.")

        else:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text is not None:
                st.success("✅ Retrieve Successfully!")
                st.text_area("Decrypted Data", value=decrypted_text, height=150)

            else:
                st.error(f"❌ Invalid passkey or data! Attempts {st.session_state.failed_attempts}")

                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts!")
                    st.session_state.menu = "Login"
                    st.rerun()

elif st.session_state.menu =="Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password", type= "password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅Login successful!")

            st.session_state.menu = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect Password!")