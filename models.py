from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    secret_key = db.Column(db.String(100))
    is_2fa_configured = db.Column(db.Boolean, default=False, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    @property
    def is_active(self):
        """Kas kasutaja konto on aktiivne."""
        return True
    
    @property
    def is_authenticated(self):
        """Kas kasutaja on autenditud."""
        return True

    @property
    def is_anonymous(self):
        """Kas see on anonüümne kasutaja."""
        return False

    def get_id(self):
        """Tagasta kasutaja ID, mida Flask-Login saab kasutada."""
        return str(self.id)