from flask import Flask, render_template, flash, redirect, url_for, session, request
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from decouple import config

app = Flask(__name__)

# Config MySQL
app.config["MYSQL_HOST"] = config("MYSQL_HOST")
app.config["MYSQL_USER"] = config("MYSQL_USER")
app.config["MYSQL_PASSWORD"] = config("MYSQL_PASSWORD")
app.config["MYSQL_DB"] = config("MYSQL_DB")
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

app.secret_key = config("SECRET_KEY")

# Init MySQL
mysql = MySQL(app)

def execute_query(query, values=None, fetch_one=False):
    cur = mysql.connection.cursor()
    if values:
        cur.execute(query, values)
    else:
        cur.execute(query)

    if fetch_one:
        result = cur.fetchone()
    else:
        result = cur.fetchall()

    cur.close()
    return result

@app.route("/")
def index():
    return render_template("home.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/articles")
def articles():
    articles = execute_query("SELECT * FROM articles")
    if articles:
        return render_template("articles.html", articles=articles)
    else:
        msg = "No Articles Found"
        return render_template("articles.html", msg=msg)

@app.route("/articles/<string:id>/")
def article(id):
    article = execute_query("SELECT * FROM articles WHERE id = %s", [id], fetch_one=True)
    return render_template("article.html", article=article)

class RegisterForm(Form):
    name = StringField("Name", [validators.Length(min=1, max=50)])
    email = StringField("Email", [validators.Length(min=6, max=50)])
    username  = StringField("Username", [validators.Length(min=4, max=25)])
    password = PasswordField("Password", [
        validators.DataRequired(),
        validators.EqualTo("confirm", message="Passwords do not match")
    ])
    confirm = PasswordField("Confirm Password")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        execute_query("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        flash("You are now registered and can log in", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password_candidate = request.form["password"]

        user = execute_query("SELECT * FROM users WHERE username = %s", [username], fetch_one=True)

        if user and sha256_crypt.verify(password_candidate, user["password"]):
            session["logged_in"] = True
            session["username"] = username
            flash("You are now logged in", "success")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid login"
            return render_template("login.html", error=error)

    return render_template("login.html")

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, please login!", "danger")
            return redirect(url_for("login"))
    return wrap

@app.route("/logout")
@is_logged_in
def logout():
    session.clear()
    flash("You are now logged out", "success")
    return redirect(url_for("login"))

@app.route("/dashboard")
@is_logged_in
def dashboard():
    articles = execute_query("SELECT * FROM articles")
    if articles:
        return render_template("dashboard.html", articles=articles)
    else:
        msg = "No Articles Found"
        return render_template("dashboard.html", msg=msg)

class ArticleForm(Form):
    title = StringField("Title", [validators.Length(min=1, max=200)])
    body  = TextAreaField("Body", [validators.Length(min=30)])

@app.route("/add_article", methods=["GET", "POST"])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        body = form.body.data

        execute_query("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)", (title, body, session["username"]))

        flash("Article Created", "success")
        return redirect(url_for("dashboard"))

    return render_template("add_article.html", form=form)

@app.route("/edit_article/<string:id>", methods=["GET", "POST"])
@is_logged_in
def edit_article(id):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])
    article = cur.fetchone()
    form = ArticleForm(request.form)
    form.title.data = article["title"]
    form.body.data = article["body"]
    if request.method == "POST" and form.validate():
        title = request.form["title"]
        body = request.form["body"]

        execute_query("UPDATE articles SET title = %s, body = %s WHERE id = %s", (title, body, id))

        flash("Article Updated", "success")
        return redirect(url_for("dashboard"))

    return render_template("edit_article.html", form=form)

@app.route("/delete_article/<string:id>", methods=["POST"])
@is_logged_in
def delete_article(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM articles WHERE id = %s", [id])
    mysql.connection.commit()
    cur.close()
    flash("Article Deleted", "success")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
