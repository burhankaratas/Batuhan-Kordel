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
    if session["logged_in"] == True:
        return render_template("app.html")
    
    elif session["logged_in"] == False:
        return render_template("index.html")

@app.route("/hakkinda")
def hakkinda():
    return render_template("hakkinda.html")

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

                mysql.connection.commit()
                cursor.close()

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
    session["logged_in"] = False
    session["username"] = "Misafir"

    flash("Başarıyla çıkış yaptınız. Hesabınıza erişmek için lütfen tekrar giriş yapınız.", "success")
    return redirect(url_for("login"))


@app.route("/forum", methods = ["GET", "POST"])
def forum():
    if session["logged_in"] == False:
        return render_template("forum.html")
    
    elif session["logged_in"] == True:
        return render_template("forum.html", username = session["username"])


@app.route("/forum/<string:id>", methods = ["GET", "POST"])
def forums(id):
    pass 

@app.route("/yeniforum", methods = ["GET", "POST"])
@login_required
def newForum():
    form = ForumForm(request.form)

    if request.method == "GET":
        return render_template("newforum.html", username = session["username"], form = form)
    
    elif request.method == "POST":
        title = form.title.data
        content = form.content.data

        cursor = mysql.connection.cursor()

        sorgu = "SELECT * FROM users WHERE username = %s"
        result = cursor.execute(sorgu, (session["username"],))

        if result > 0:
            data = cursor.fetchone()

            userid = data["id"]

            sorgu2 = "INSERT INTO topics (userid, title, content) VALUES (%s, %s, %s)"
            cursor.execute(sorgu2, (userid, title, content))

            mysql.connection.commit()
            cursor.close()

            flash("Forumunuz başarıyla yayımlandı. Forumlarımı görüntüle kısmından forumunuza erişebilirsiniz.", "success")
            return redirect(url_for("forum"))
        
        else:
            flash("Beklenmedik bir hata ile karşılaşıldı. Lütfen giriş yapıp tekrar deneyiniz.", "danger")
            return redirect(url_for("logout"))
    




        





class RegisterForm(Form):
    username = StringField(validators=[validators.length(min=5, max=25),validators.InputRequired()])
    email = StringField(validators=[validators.Email(), validators.InputRequired()])
    phone = StringField(validators=[validators.length(min=10, max=10), validators.InputRequired()])
    password = PasswordField(validators=[validators.length(min=8, max=40), validators.InputRequired()])
    passwordAgain = PasswordField(validators=[validators.length(min=8, max=40),  validators.InputRequired()])

class LoginForm(Form):
    username = StringField()
    password = PasswordField()

class ForumForm(Form):
    title = StringField(validators=[validators.InputRequired(), validators.length(min=3, max=50)])
    content = TextAreaField(validators=[validators.InputRequired(), validators.length(min=10, max=1000)])


if __name__ == "__main__":
    app.run(debug= True)