from flask import Flask, redirect, url_for, request, render_template, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_principal import Principal, Permission, RoleNeed, identity_loaded, UserNeed, Identity, AnonymousIdentity, \
    identity_changed
from werkzeug.exceptions import Forbidden

app = Flask(__name__)
app.secret_key = 'secret-key'  # Troque para uma chave segura em produção.

# Configuração do Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuração do Flask-Principal
principals = Principal(app)

# Definir permissões de acordo com o papel (role)
admin_permission = Permission(RoleNeed('admin'))
user_permission = Permission(RoleNeed('user'))

# Simular um banco de dados de usuários
users = {
    "admin": {"password": "adminpass", "role": "admin"},
    "user": {"password": "userpass", "role": "user"}
}


# Classe User para o Flask-Login
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role


@login_manager.user_loader
def load_user(user_id):
    user_data = users.get(user_id)
    if user_data:
        return User(user_id, user_data["role"])
    return None


# Atualizar a identidade com base no papel do usuário
@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if current_user.is_authenticated:
        identity.provides.add(UserNeed(current_user.id))
        identity.provides.add(RoleNeed(current_user.role))


# Rota de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)

        if user and user['password'] == password:
            user_obj = User(username, user['role'])
            login_user(user_obj)
            identity_changed.send(app, identity=Identity(user_obj.id))
            return redirect(url_for('index'))
        return 'Invalid credentials'
    return render_template('login.html')


# Rota protegida para admin
@app.route('/admin')
@login_required
def admin():
    if not admin_permission.can():
        return redirect(url_for('forbidden'))
    return Response("Hello, Admin!")


# Rota protegida para usuários comuns
@app.route('/dashboard')
@login_required
def dashboard():
    if not user_permission.can():
        return redirect(url_for('forbidden'))
    return Response("Hello, User!")


# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    identity_changed.send(app, identity=AnonymousIdentity())
    return redirect(url_for('login'))


# Rota principal
@app.route('/')
def index():
    if current_user.is_authenticated:
        return f"Hello, {current_user.id}! Role: {current_user.role}"
    return "Welcome! Please <a href='/login'>login</a>."


# Rota para a página de erro 403
@app.route('/forbidden')
def forbidden():
    return render_template('403.html'), 403


if __name__ == '__main__':
    app.run(debug=True)
