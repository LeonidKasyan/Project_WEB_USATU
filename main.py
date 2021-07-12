from flask import Flask, render_template, url_for, redirect
from data import db_session
from data.users import User
from data.registerForm import RegisterForm
from data.loginForm import LoginForm
from flask_login import LoginManager, login_user, logout_user, login_required
from data.table_vaz import table_vaz
from data.table_gaz import table_gaz
from data.table_yaz import table_yaz
from data.table_paz import table_paz




db_session.global_init("db/blogs.sqlite")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Admin123'
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    session = db_session.create_session()
    return session.query(User).get(user_id)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route("/")
@app.route('/home')
def home():
    return render_template('home.html')


@app.route('/gaz')
def gaz():
    return render_template('gaz.html')


@app.route('/vaz')
def vaz():
    return render_template('vaz.html')


@app.route('/yaz')
def yaz():
    return render_template('yaz.html')


@app.route('/paz')
def paz():
    return render_template('paz.html')


@app.route('/order')
def order():
    return render_template('order.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        session = db_session.create_session()
        user = session.query(User).filter(User.email == form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            return redirect("/")
        return render_template('login.html', message="Неправильный логин или пароль", form=form)
    return render_template('login.html', title='Авторизация', form=form)


@app.route('/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Регистрация',form=form, message="Пароли не совпадают")
        session = db_session.create_session()
        if session.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Регистрация', form=form, message="Такой пользователь уже есть")
        user = User(name=form.name.data, email=form.email.data, about=form.about.data)
        user.set_password(form.password.data)
        session.add(user)
        session.commit()
        return redirect('/login')
    return render_template('register.html', title='Регистрация', form=form)



if __name__ == "__main__":
    db_session.global_init("db/blogs.sqlite")
    #table_vaz()
    #table_gaz()
    #table_yaz()
    #table_paz()
    app.run()
