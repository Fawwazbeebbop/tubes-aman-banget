from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import sqlite3
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

import html

app = Flask(__name__)
app.secret_key = "supersecretkey123"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///students.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# =====================================
# USER MODEL (REGISTER & LOGIN)
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
            flash("Silakan login dulu.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# =====================================
# HOME -> redirect
# =====================================
@app.route("/home")
def home():
    # optional: kalau akses /home, arahkan sesuai login atau tidak
    if "user" in session:
        return redirect(url_for("index"))
    return redirect(url_for("login"))

# =====================================
# REGISTER PAGE
# =====================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not username or not password:
            flash("Username dan password wajib diisi.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Password dan konfirmasi tidak sama.", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(username=username).first():
            flash("Username sudah digunakan!", "error")
            return redirect(url_for("register"))

        hashed_pw = generate_password_hash(password)
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash("Akun berhasil dibuat. Silakan login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# =====================================
# LOGIN PAGE + SESSION
# =====================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["user"] = username
            flash("Login berhasil.", "success")
            return redirect(url_for("index"))

        flash("Login gagal! Username atau password salah.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")

# =====================================
# LOGOUT
# =====================================
@app.route("/logout")
@login_required
def logout():
    session.pop("user", None)
    flash("Kamu sudah logout.", "success")
    return redirect(url_for("login"))

# =====================================
# HALAMAN UTAMA (DILINDUNGI)
# =====================================
@app.route("/")
@login_required
def index():
    students = db.session.execute(text("SELECT * FROM student")).fetchall()
    return render_template("index.html", students=students)

# =====================================
# ADD STUDENT (DILINDUNGI)
# =====================================
@app.route("/add", methods=["POST"])
@login_required
def add_student():
    name = html.escape(request.form['name'])
    age = html.escape(request.form['age'])
    grade = html.escape(request.form['grade'])

    if not name or not age or not grade:
        flash("Semua field (name, age, grade) harus diisi.", "error")
        return redirect(url_for("index"))

    # ✅ lebih aman: parameterized query (hindari SQL injection)
    connection = sqlite3.connect("instance/students.db")
    cursor = connection.cursor()

    query = "INSERT INTO student (name, age, grade) VALUES (?, ?, ?)"
    cursor.execute(query, (name, age, grade))
    connection.commit()
    connection.close()

    flash("Data student berhasil ditambahkan.", "success")
    return redirect(url_for("index"))

# =====================================
# DELETE STUDENT (DILINDUNGI)
# =====================================
@app.route("/delete/<int:id>")
@login_required
def delete_student(id):
    # ✅ parameterized
    db.session.execute(text("DELETE FROM student WHERE id = :id"), {"id": id})
    db.session.commit()
    flash("Data student berhasil dihapus.", "success")
    return redirect(url_for("index"))

# =====================================
# EDIT STUDENT (DILINDUNGI)
# =====================================
@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_student(id):
    if request.method == 'POST':
        name = html.escape(request.form['name'])
        age = html.escape(request.form['age'])
        grade = html.escape(request.form['grade'])

        db.session.execute(text(f"UPDATE student SET name='{name}', age={age}, grade='{grade}' WHERE id={id}"))
        db.session.commit()
        flash("Data student berhasil diupdate.", "success")
        return redirect(url_for("index"))

    student = db.session.execute(text("SELECT * FROM student WHERE id = :id"), {"id": id}).fetchone()
    return render_template("edit.html", student=student)

# =====================================
# RUN APP
# =====================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)
