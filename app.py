import os
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_bootstrap import Bootstrap
from flask_migrate import Migrate

from models import User, db

from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from flask_qrcode import QRcode

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE')
app.config['TEMPLATES_AUTO_RELOAD'] = os.getenv('TEMPLATES_AUTO_RELOAD', 'default_value').lower() in ['true', '1', 't', 'y', 'yes']
db.init_app(app) #registreeri model.py-s sisalduv db cursor

migrate = Migrate(app, db)
bootstrap = Bootstrap(app)
QRcode(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        re_password = request.form.get('re_password')
        if password == re_password:
            if User.query.filter_by(username=username).first():
                return 'See kasutajanimi on juba kasutuses.'
            new_user = User(username=username)
            new_user.set_password(password)
            new_user.secret_key = pyotp.random_base32()
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        else:
            flash('The passwords do not match.', 'error')
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # Kui kasutaja on juba autentitud, suuna 2FA seadistamisele
        return redirect(url_for('setup_and_verify_2fa'))
    else:
        if request.method == 'POST':
            user = User.query.filter_by(username=request.form.get('username')).first()
            if user and user.check_password(request.form.get('password')):
                login_user(user)
                return redirect(url_for('setup_and_verify_2fa'))
            else:
                flash('Wrong usrname or password.', 'error')
                
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    user = current_user
    user.is_2fa_configured = False
    db.session.commit()
    logout_user()  # Logib kasutaja välja
    return redirect(url_for('protected'))  

@app.route('/setup_and_verify_2fa', methods=['GET', 'POST'])
@login_required
def setup_and_verify_2fa():
    user = current_user
    if request.method == 'POST':
        totp = pyotp.TOTP(user.secret_key)
        if totp.verify(request.form.get('2fa_code')):
            user.is_2fa_configured = True
            db.session.commit()
            return redirect(url_for('protected'))
        else:
            flash('Vale 2FA kood. Palun proovige uuesti.', 'error')

    totp_uri = pyotp.totp.TOTP(user.secret_key).provisioning_uri(name=user.username, issuer_name="FLASK APP: Kasutaja:")
    return render_template('login.html', totp_uri=totp_uri)

@app.route('/protected')
@login_required
def protected():
    return render_template('protected.html', user=current_user.username)

if __name__ == '__main__':
    app.run(debug=True)