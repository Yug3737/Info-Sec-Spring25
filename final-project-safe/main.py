import re
import sqlite3
import hashlib
from dotenv import dotenv_values
from Crypto.Cipher import AES
from secrets import token_bytes
from flask import Flask, render_template, request, redirect, url_for, session

DB_PATH = r".\\patelDB.db"
app = Flask(__name__)

text = None
with open("secret_key.txt") as f:
    text = f.read()
app.secret_key = text.split('=')[1]

def hash_password(password):
    password_bytes = password.encode('utf-8')
    hash_object = hashlib.sha256(password_bytes)
    return hash_object.hexdigest()

def encrypt(plaintext_string):
    key = token_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_string.encode('ascii'))
    return nonce, ciphertext, tag

def populate_table():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    sql = """
            CREATE TABLE IF NOT EXISTS registration_info(
            ID INTEGER primary key autoincrement,
            username text,
            password text,
            address text,
            funfact text
            );
            """
    cursor.execute(sql)

    sql = """
        DELETE FROM registration_info;
        """
    cursor.execute(sql)

    sample_passwords = dotenv_values(".env")
    lennice_password, yug_password, nick_password = sample_passwords['lennice_password'], sample_passwords['yug_password'], sample_passwords['nick_password']
    hashed_yug_password, hashed_lennice_password, hashed_nick_password = hash_password(yug_password), hash_password(lennice_password), hash_password(nick_password)
    yug_address, nick_address, lennice_address = 'Solon, OH', '345 Flats, Kent, OH', 'Euclid, OH'
    nonce1, encrypted_yug_address, tag1  = encrypt(yug_address)
    nonce2, encrypted_nick_address, tag2  = encrypt(nick_address)
    nonce3, encrypted_lennice_address, tag3 = encrypt(lennice_address)

    sample_users = [
        ('yug', hashed_yug_password, encrypted_yug_address, 'unfun fact'),
        ('nick', hashed_nick_password, encrypted_nick_address, 'can do 40 push ups in a go'),
        ('lennice', hashed_lennice_password, encrypted_lennice_address, 'works at charles shwab')
    ]

    for username, password, address, funfact in sample_users:
        sql = "INSERT INTO registration_info (username, password, address, funfact) VALUES (?,?,?,?);"
        cursor.execute(sql, (username, password, address, funfact))

    connection.commit()
    cursor.close()
    connection.close()


@app.route("/")
def index():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    sql = """
            select username, password, address, funfact
            from registration_info
            """
    cursor.execute(sql)
    users = cursor.fetchall()
    cursor.close()
    connection.close()

    if "loggedin" in session:
        return render_template("index.html", users=users, username=session["username"])
    else:
        return render_template("index.html", users=users, username=None)


# SQLi safe code
@app.route("/register_user", methods=["POST"])
def register_user():
    if (
        request.method == "POST"
        and "username" in request.form
        and "password" in request.form
        and "address" in request.form
        and "funfact" in request.form
    ):
        username = request.form["username"]
        password = request.form["password"]
        address = request.form["address"]
        funfact = request.form["funfact"]

        username_regex = r"^[a-zA-Z0-9_.-]{3,20}$"
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$"
        address_regex = r"^[a-zA-Z0-9\s,'./#-]{5,}$"
        funfact_regex = r"^[a-zA-Z0-9\s.,!?'()-]{3,}$"

        if not re.match(username_regex, username):
            return "Invalid username format.", 400
        if not re.match(password_regex, password):
            return "Invalid password format.", 400
        if not re.match(address_regex, address):
            return "Invalid address format.", 400
        if not re.match(funfact_regex, funfact):
            return "Invalid fun fact format.", 400

        hashed_password = hash_password(password)
        nonce, encrypted_address, tag = encrypt(address)

        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        insertion_data = (username, hashed_password, encrypted_address, funfact)
        sql = f"""
            INSERT INTO registration_info (username, password, address, funfact)
            VALUES (?,?,?,?);
        """
        # execute function only allows 1 sql query to be executed at a time.
        # this step prevents multiple queries(which are often sql injections) to be executed at once.
        cursor.execute(sql, insertion_data)
        connection.commit()
        cursor.close()
        connection.close()
        return redirect(url_for("index"))
    else:
        return "Invalid submission", 400


@app.route("/login", methods=["POST"])
def user_login():
    if (
        request.method == "POST"
        and "username" in request.form
        and "password" in request.form
    ):
        username = request.form["username"]
        password = request.form["password"]
        hashed_passowrd = hash_password(password)

        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        sql = """
                SELECT * from registration_info where username = %s and password = %s;
                """
        print(f"[Attempted SQL] => {sql}")
        user_found = None
        try:
            cursor.execute(sql, (username, hashed_passowrd))
            users = cursor.fetchone()
            user_found = True if len(users) > 0 else False
        except sqlite3.Error as err:
            print(f"SQL Error during login: {err}")
            cursor.close()
            connection.close()
            return "Database error during login. Please try again later.", 500

        cursor.close()
        connection.close()

        if user_found:
            session["username"] = username
            session["password"] = hashed_passowrd
            return redirect(url_for("welcome"))
        else:
            return "Invalid credentials", 403
    else:
        return "Bad Request: username or password missing", 400

@app.errorhandler(sqlite3.Error)
def handle_sqlite_error(error):
    print(f"SQLite Error Handler: {error}")
    return "A database error occured. Please try again later.", 500

@app.route("/welcome")
def welcome():
    if "username" not in session:
        return redirect(url_for("index"))
    return render_template("welcome.html", username=session["username"])


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    populate_table()
    app.run(port=8888, debug=True)
