from flask import Flask, request, jsonify
from flask_cors import CORS
import pymysql
from pymysql.err import IntegrityError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import re
import secrets

SALT_FILE = "salt.bin"
# Database configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = ""
DB_NAME = "securevault_db"
TABLE_NAME = "tbl_createaccount"
SAVEPASSWORD_TABLE_NAME = "tbl_savepassword"
PASSWORD_TABLE_NAME = "password_table"
# Flask app
app = Flask(__name__)
CORS(app, supports_credentials=True, origins="*")  # Not safe for production
def get_or_create_salt() -> bytes:
    """Generates a salt once and reuses it on future runs."""
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    else:
        salt = os.urandom(16)
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if re.match(pattern, email):
        return True
    else:
        return False
# Custom mask function
def mask_password(password: str) -> str:
    # Replace each character with a unique symbol or pattern
    masked_password = ''.join(chr(ord(c) + 100) for c in password)  # Example of shifting the ASCII value by 100
    return masked_password

# Custom demask function
def demask_password(masked_password: str) -> str:
    # Reverse the transformation, by shifting back the ASCII value by 100
    original_password = ''.join(chr(ord(c) - 100) for c in masked_password)
    return original_password

# Custom mask function
#def mask_password(password: str) -> str:
  #  masked_password = ''.join(chr((ord(c) + 100 - 32) % 95 + 32) for c in password)
  #  return masked_password

#def demask_password(masked_password: str) -> str:
   # original_password = ''.join(chr((ord(c) - 100 - 32) % 95 + 32) for c in masked_password)
  #  return original_password

def isValid_url(url):
    parsed = urlparse(url)
    return all([parsed.netloc])


# Encryption key generation (store securely in env variables)
def generate_key():
    password = os.environ.get('ENCRYPTION_PASSWORD', 'default_password').encode()
    salt = get_or_create_salt()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

encryption_key = generate_key()
def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data without padding (CFB mode)."""
    try:
        # Decode base64-encoded data
        encrypted_data_bytes = urlsafe_b64decode(encrypted_data)
        
        # Extract IV and encrypted content
        iv = encrypted_data_bytes[:16]  # IV is the first 16 bytes
        encrypted_content = encrypted_data_bytes[16:]  # The rest is the encrypted data
        
        # Initialize the cipher with the same key and IV
        cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt the content directly (no padding to remove)
        decrypted_data = decryptor.update(encrypted_content) + decryptor.finalize()

        # Check if decrypted data is text (i.e., UTF-8 encoded)
        try:
            return decrypted_data.decode('utf-8')  # Try decoding as UTF-8 text
        except UnicodeDecodeError:
            raise ValueError("Decryption successful but the data is not UTF-8 encoded text.")
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")


# Encrypt data
def encrypt_data(data: str) -> str:
     print(encryption_key)
     """Encrypt sensitive data without padding (CFB mode)."""
     iv = os.urandom(16)  # Initialization vector (IV) for CFB mode
     cipher = Cipher(algorithms.AES(encryption_key), modes.CFB(iv), backend=default_backend())
     encryptor = cipher.encryptor()

     # Encrypt without adding padding
     encrypted = encryptor.update(data.encode()) + encryptor.finalize()

     # Concatenate IV and encrypted data, then base64 encode it
     return urlsafe_b64encode(iv + encrypted).decode()


# Database connection helper
def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

# API endpoint to register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    master_password = data.get('master_password')
    if not email or not master_password:
        return jsonify({"error": "Email and master password are required."}), 400

    # Encrypt the master password
    encrypted_password = encrypt_data(master_password)
    facetoken = secrets.token_hex(16)
    try:
        # Save to database
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"INSERT INTO {TABLE_NAME} (email, mpassword, faceidtoken) VALUES (%s, %s, %s)"
        cursor.execute(query, (email, encrypted_password, facetoken))
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({"success": "User registered successfully."}), 201
    except IntegrityError as ie: 
        print(ie.args)
        if ie.args[0] == 1062:
            return jsonify({"error": "This email is already registered. Please use a different one."}), 409
        else: 
            return jsonify({"error": "Database Integrity Error"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST']) 
def login():
    data = request.json
    email = data.get('email')
    pwd = data.get('password')
    if not email or not pwd: 
        return jsonify({"error": "Email and master password are required."}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Enter a valid email address"}), 400
    try: 
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"SELECT * FROM {TABLE_NAME} WHERE email = %s"
        cursor.execute(query,email)
        rows = cursor.fetchall()
        print("rows",rows)
        if rows:
            for data in rows: 
                decrypted_pwd = decrypt_data(data[2])
                print(f"data: {data} decrypted pas:{decrypted_pwd}")
                if data[1] == email and pwd == decrypted_pwd:
                    return { "uid":data[0],
                            "email":data[1],
                            "password":decrypted_pwd,
                            "faceidtoken":data[3]
                    }
                else: 
                    return jsonify({"error":"Invalid email or password"}), 401
        else: 
            return jsonify({"error": "Account doesnot exist !!"}), 401
        
    except Exception as e: 
        return jsonify({"error":str(e)})

@app.route('/savepassword', methods=['POST'])
def save_password():
    data = request.json
    sitename = data.get('sitename') 
    username = data.get('uname')
    password = data.get('password')
    uid = int(data.get('uid'))
    site_url = data.get('url')
    print(sitename,username,password,uid,site_url)
    if not sitename or not username or not password or not site_url: 
        return jsonify({"error":"All field are required!!"}), 401
    if not isValid_url(site_url):
        return jsonify({"error":"invalid url!!"}), 405
    encrypted_pwd = encrypt_data(password)
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"insert into {SAVEPASSWORD_TABLE_NAME} (sitename, username, password, url, uid) VALUES (%s, %s, %s, %s, %s)"
        cursor.execute(query, (sitename,username,encrypted_pwd,site_url,uid))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({"success":"password saved successfully"})
    except Exception as e: 
        return jsonify({"error":str(e)}), 500
#update the saved password 
@app.route('/update', methods = ['POST'])
def updateSavedPassword():
    data = request.json 
    sitename = data.get('sitename')
    username = data.get('uname')
    password = data.get('password')
    uid = int(data.get('uid'))
    site_url = data.get('url')
    if not sitename or not username or password or not site_url: 
        return jsonify({"error":"All field are required!!"}), 401
    if not isValid_url(site_url):
        return jsonify({"error":"invalid url!!"}), 405
    encrypted_pwd = encrypt_data(password)
    try: 
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"UPDATE TABLE {SAVEPASSWORD_TABLE_NAME} SET sitename = %s, username = %s, password = %s, url = %s WHERE uid = %s"
        cursor.execute(query, (sitename,username,encrypted_pwd,site_url,uid))
        connection.commit()
        if cursor.rowcount > 0: 
            result = jsonify({"success": "successfully saved"}), 1000
        else:
            result = jsonify({"error": "something went wrong while updating"}), 1002
        cursor.close()
        connection.close()
        return result
    except Exception as e: 
        return jsonify({"error":str(e)}), 500
#pawned password 
@app.route('/checkPasswordIsPawned', methods = ['POST'])
def checkPawned():
    try: 
        data = request.json
        password = data.get('password')
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"SELECT * FROM {PASSWORD_TABLE_NAME} WHERE password = %s"
        cursor.execute(query,(password))
        rows = cursor.fetchall() 
        print("password", rows)
        if len(rows) > 0: 
            return jsonify({"Yes": "Pawned password"}), 200
        else: 
            return jsonify({"No": "password not pawned"}), 202
    except Exception as e: 
        return jsonify({"error": str(e)}), 500
# API endpoint to retrieve masked user data (for admin or diagnostic purposes)
@app.route('/users/<email>', methods=['GET'])
def get_user(email):
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"SELECT email, mpassword FROM {TABLE_NAME} WHERE email = %s"
        cursor.execute(query, (email))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if not user:
            return jsonify({"error": "User not found."}), 404

        email, encrypted_password = user
        masked_password = decrypt_data(encrypted_password)

        return jsonify({
            "email": email,
            "mpassword": masked_password
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/getAllPasswords', methods=['POST'])
def fetchAllPassword():
    try: 
        data = request.json
        uid = int(data.get('uid'))
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"SELECT id, sitename, username, password, url FROM {SAVEPASSWORD_TABLE_NAME} WHERE uid = %s"
        cursor.execute(query, (uid))
        data = cursor.fetchall()
        cursor.close()
        connection.close()
        savedPwds = []
        for d in data:
            savedPwds.append({'id': d[0],
                              'sitename': d[1],
                              'username': d[2],
                              'password': decrypt_data(d[3]),
                              'url': d[4]
                              })
        
        return savedPwds
    except Exception as e: 
        return jsonify({"error": str(e)}), 500
@app.route('/deleteaccount', methods = ['POST'])
def deleteAccount():
    try:
        data = request.json
        uid = int(data.get('uid'))
        connection = get_db_connection()
        cursor = connection.cursor()
        query = f"DELETE From {TABLE_NAME} WHERE uid = %s"
        cursor.execute(query, uid)
        connection.commit()
        if cursor.rowcount > 0:
            return jsonify({"success":"account deleted successfully"}), 200
        else: 
            return jsonify({"error":"unable to delete account"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally: 
        if connection: 
            cursor.close()
            connection.close()
        
@app.route('/updatepassword', methods = ['POST'])
def updatePassword():
    data = request.json
    password = data.get('password')
    uid = int(data.get('uid'))
    if not password:
        return jsonify({"error":"All field are required!!"}), 401
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        encrypted_pwd = encrypt_data(password)
        query = f"UPDATE {TABLE_NAME} SET mpassword = %s WHERE uid = %s"
        cursor.execute(query,(encrypted_pwd, uid))
        connection.commit()
        print("cursor.rowcount ", cursor.rowcount)
        if cursor.rowcount > 0: 
            return jsonify({"success":"Master Password Updated Successfully !!"}), 200
        else:
            return jsonify({"error":"Update went wrong!!"}), 404
    except Exception as e:
            return jsonify({"error": str(e)}), 500
    finally:
        if connection:
            cursor.close()
            connection.close()
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5555, debug=True)


