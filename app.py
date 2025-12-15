from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash   # === Added ===

import html

app = Flask(__name__)
app.secret_key = "supersecretkey123"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///students.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# =====================================
# USER MODEL (REGISTER & LOGIN)  === Added ===
# =====================================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# =====================================
# STUDENT MODEL
# =====================================
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    grade = db.Column(db.String(10), nullable=False)


# =====================================
# LOGIN REQUIRED (MITIGASI CWE-306)
# =====================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


# =====================================
# REGISTER PAGE  === Added ===
# =====================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # cek apakah user sudah ada
        if User.query.filter_by(username=username).first():
            return "Username sudah digunakan!"

        # simpan user baru
        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        # === langsung arahkan ke login ===
        return redirect(url_for("login"))

    return """
    <h2>Register</h2>
    <form method="POST">
        <input name="username" placeholder="Username"><br>
        <input name="password" type="password" placeholder="Password"><br>
        <button type="submit">Daftar</button>
    </form>

    <a href="/login">Ke Login</a>
    """



# =====================================
# LOGIN PAGE + SESSION
# =====================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["user"] = username
            return redirect(url_for("index"))

        return "Login gagal! Username atau password salah."

    return """
    <h2>Login</h2>
    <form method="POST">
        <input name="username" placeholder="Username"><br>
        <input name="password" type="password" placeholder="Password"><br>
        <button type="submit">Login</button>
    </form>

    <a href="/register">Belum punya akun? Daftar</a>
    """


# =====================================
# LOGOUT
# =====================================
@app.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# =====================================
# HALAMAN UTAMA (DILINDUNGI)
# =====================================
@app.route('/')
@login_required
def index():
    students = db.session.execute(text('SELECT * FROM student')).fetchall()
    return render_template('index.html', students=students)


# =====================================
# ADD STUDENT (DILINDUNGI)
# =====================================
@app.route('/add', methods=['POST'])
@login_required
def add_student():
    name = html.escape(request.form['name'])
    age = html.escape(request.form['age'])
    grade = html.escape(request.form['grade'])

    connection = sqlite3.connect('instance/students.db')
    cursor = connection.cursor()

    query = f"INSERT INTO student (name, age, grade) VALUES ('{name}', {age}, '{grade}')"
    cursor.execute(query)
    connection.commit()
    connection.close()

    return redirect(url_for('index'))


# =====================================
# DELETE STUDENT (DILINDUNGI)
# =====================================
@app.route('/delete/<string:id>')
@login_required
def delete_student(id):
    db.session.execute(text(f"DELETE FROM student WHERE id={id}"))
    db.session.commit()
    return redirect(url_for('index'))


# =====================================
# EDIT STUDENT (DILINDUNGI)
# =====================================
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_student(id):
    if request.method == 'POST':
        name = html.escape(request.form['name'])
        age = html.escape(request.form['age'])
        grade = html.escape(request.form['grade'])

        db.session.execute(text(f"UPDATE student SET name='{name}', age={age}, grade='{grade}' WHERE id={id}"))
        db.session.commit()
        return redirect(url_for('index'))

    student = db.session.execute(text(f"SELECT * FROM student WHERE id={id}")).fetchone()
    return render_template('edit.html', student=student)


# =====================================
# RUN APP
# =====================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
