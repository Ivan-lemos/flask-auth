from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user


app = Flask(__name__)
app.config['SECRET_KEY'] = {YOUR-SECRET-KEY}

# Configurações do banco
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Configuração do LoginManager
login_manager = LoginManager()
login_manager.login_view = 'login'  # Redireciona usuários não logados para esta rota automaticamente
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Busca o usuário pelo id, necessário para o Flask-Login
    return db.get(User, int(user_id))

# Modelo de usuário
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(1000), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get('email')
        
        # Verifica se usuário já existe
        existing_user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        if existing_user:
            flash("You've already signed up with that email, log in instead!", "warning")
            return redirect(url_for('login'))

        # Cria hash da senha
        hashed_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=email,
            password=hashed_password,
            name=request.form.get('name'),
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)  # Loga o usuário automaticamente após registro
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()
        
        if not user:
            flash("That email does not exist, please try again.", "danger")
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.', "danger")
            return redirect(url_for('login'))
        
        login_user(user)
        return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)

@app.route('/secrets')
@login_required
def secrets():
    return render_template("secrets.html", name=current_user.name, logged_in=True)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))

@app.route('/download')
@login_required
def download():
    # 'static' é o diretório raiz para arquivos estáticos por padrão
    return send_from_directory('static/files', filename="cheat_sheet.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
