from myapp import db, User
from werkzeug.security import generate_password_hash
from flask import Flask


# Sektion für Flask-Anwendung
app = Flask(__name__)
# Konfiguration für SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://myapp:ad7822Hldasd@localhost/myapp' 
db.init_app(app)


def create_default_user():
    with app.app_context():
        db.create_all()  # Falls noch nicht geschehen, Tabellen erstellen
        
        # Prüfen, ob der Default-User existiert
        if not User.query.filter_by(username="admin").first():
            hashed_password = generate_password_hash("Hallodu123", method="pbkdf2:sha256")
            default_user = User(username="admin", password=hashed_password)
            
            db.session.add(default_user)
            db.session.commit()
            print("Default-User 'admin' wurde erstellt.")
        else:
            print("Default-User existiert bereits.")

if __name__ == "__main__":
    create_default_user()