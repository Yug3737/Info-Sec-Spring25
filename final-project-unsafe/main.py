import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = r"C:\\Users\\yugpa\\KSU\\Spring25\\InfoSec\\final-project-unsafe\\patelDB.db"

app = Flask(__name__)
app.secret_key = "secret_key"


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

    sql = """
            INSERT INTO registration_info (username, password, address, funfact)
            VALUES ('yug', 'abcd', 'solon', 'unfun fact');
            """
    cursor.execute(sql)
    sql = """
            INSERT INTO registration_info (username, password, address, funfact)
            VALUES ('lennice', 'pqrs', 'euclid', 'works at charles shwab');
            """
    cursor.execute(sql)
    sql = """
            INSERT INTO registration_info (username, password, address, funfact)
            VALUES ('nick', 'xyz', '345 flats', 'can do 40 push ups in a go');
            """
    cursor.execute(sql)
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


# SQLi vulnerable code
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

        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        sql = f"""
            INSERT INTO registration_info (username, password, address, funfact)
            VALUES ('{username}', '{password}', '{address}', '{funfact}');

        """
        # only for demo purposes
        # executescript function allows execution of multiple sql queries
        # which allows some SQL injections to be executed
        cursor.executescript(sql)
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

        connection = sqlite3.connect(DB_PATH)
        cursor = connection.cursor()
        sql = f"""
                SELECT * from registration_info where username = '{username}' and password = '{password}';
                """
        # ' OR 1=1 --
        print(f"[Injected SQL] => {sql}")
        user_found = None
        try:
            cursor.execute(sql)
            users = cursor.fetchone()
            print(users)
            print(type(users))
            user_found = True if len(users) > 0 else False
        except Exception as ex:
            user_found = False
            print(f"SQL Error: {ex}")

        cursor.close()
        connection.close()

        if user_found:
            session["username"] = username
            session["password"] = password
            return redirect(url_for("welcome"))
        else:
            return "Invalid credentials", 403
    else:
        return "Bad Request, username or password missing", 400


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
    app.run(port=7777, debug=True)
