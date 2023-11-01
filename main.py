from flask import Flask,render_template,flash,redirect,url_for,session,logging,request,g
from flask_mysqldb import MySQL
from wtforms import Form,StringField,TextAreaField,PasswordField,validators, SubmitField
from passlib.hash import sha256_crypt 
from functools import wraps
import hashlib


app = Flask(__name__)
app.secret_key= "isdfgrhsri"


app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "kordelmusic"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:
            return f(*args, **kwargs)
        else:
            flash("Bu sayfayı görüntüleme izniniz yok", "danger")
            return redirect(url_for("index"))
    return decorated_function



@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods = ["GET", "POST"])
def register():
    form = RegisterForm(request.form)

    if request.method == "GET":
        return render_template("register.html", form = form)
    
    elif request.method == "POST":
        username = form.username.data
        email = form.email.data
        phone = form.phone.data
        password = form.password.data
        passwordAgain = form.passwordAgain.data

        if password == passwordAgain and form.validate():
            hashedPassword = sha256_crypt.encrypt(password)

            cursor = mysql.connection.cursor()

            sorgu = "INSERT INTO users (username, email, phone, password) VALUES (%s, %s, %s, %s)"

            cursor.execute(sorgu, (username, email, phone, hashedPassword))
            mysql.connection.commit()
            cursor.close()

            flash("Kayıt olma işlemi başarıyla gerçekleştirildi. Lütfen giriş yapınız.", "success")
            return redirect(url_for("login"))
        
        else:
            flash("Şifreler birbiri ile eşleşmiyor. Lütfen şifrenizi tekrar giriniz", "danger")
            return redirect(url_for("register"))
    


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)

    if request.method == "GET":
        return render_template("login.html", form=form)
    
    elif request.method == "POST":
        usernameData = form.username.data
        passwordData = form.password.data

        cursor = mysql.connection.cursor()

        sorgu = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(sorgu, (usernameData,))

        if result > 0:
            data = cursor.fetchone()

            stored_password = data["password"]

            if sha256_crypt.verify(passwordData, stored_password):
                session["logged_in"] = True
                session["username"] = usernameData

                flash("Hesabınıza başarıyla giriş yaptınız.", "success")
                return redirect(url_for("index"))
            
            else:
                flash("Hatalı şifre. Lütfen tekrar deneyiniz.", "danger")
                return redirect(url_for("login"))
        
        else:
            flash("Böyle bir kullanıcı yok veya kullanıcı adını yanlış girdiniz. Lütfen tekrar deneyiniz.", "danger")
            return redirect(url_for("login"))


@app.route("/logout")
@login_required  
def logout():
    session.clear()

    flash("Başarıyla çıkış yaptınız. Hesabınıza erişmek için lütfen tekrar giriş yapınız.", "success")
    return redirect(url_for("login"))


class RegisterForm(Form):
    username = StringField(validators=[validators.length(min=5, max=25),validators.InputRequired()])
    email = StringField(validators=[validators.Email(), validators.InputRequired()])
    phone = StringField(validators=[validators.length(min=10, max=10), validators.InputRequired()])
    password = PasswordField(validators=[validators.length(min=8, max=40), validators.InputRequired()])
    passwordAgain = PasswordField(validators=[validators.length(min=8, max=40),  validators.InputRequired()])


class LoginForm(Form):
    username = StringField()
    password = PasswordField()

if __name__ == "__main__":
    app.run(debug= True)