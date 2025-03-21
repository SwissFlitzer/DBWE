from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
import jwt
import datetime
from functools import wraps

# App Initialisierung & Konfig der Parameter
app = Flask(__name__)
app.config['SECRET_KEY'] = 'bbbbbbbbbbbb'  # Für die Sitzung und Sicherheit
app.config['WTF_CSRF_SECRET_KEY'] = 'aaaaaaa'  # Für das CSRF-Token
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://myapp:ad7822Hldasd@localhost/myapp'  # URL für deine MariaDB
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Verhindert unnötige Speicherverbrauch in Flask

# DB Initialisierung
db = SQLAlchemy(app)

# Aktiviert den CSRF-Schutz
csrf = CSRFProtect()
csrf.init_app(app)

# Login Manager Initialisierung
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Zeigt zur Login-Seite, wenn der Benutzer nicht eingeloggt ist


# DB Modelle
class User(db.Model, UserMixin):
    __tablename__ = 'user' 
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)  # Längere Spalte für das Passwort
    
class Car(db.Model):
    __tablename__ = 'car'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    car_name = db.Column(db.String(100), unique=False, nullable=False)  # Keine UNIQUE-Beschränkung, falls mehrere Benutzer denselben Autonamen nutzen
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Verknüpfung zum Benutzer
    user = db.relationship('User', backref=db.backref('user_cars', lazy=True))  # Beziehung zum Benutzer

class CarFuelLog(db.Model):
    __tablename__ = 'car_fuel_log'
    id = db.Column(db.Integer, primary_key=True)
    car_id = db.Column(db.Integer, db.ForeignKey('car.id'), nullable=False)  # Verknüpfung zum Auto
    distance = db.Column(db.Float, nullable=False)
    fuel = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Verknüpfung zum Benutzer
    user = db.relationship('User', backref=db.backref('fuel_logs', lazy=True))  # Beziehung zum Benutzer
    car = db.relationship('Car', backref=db.backref('fuel_logs', lazy=True))  # Beziehung zum Auto

# Objekte initieren aus DB
def __init__(self, car_id, distance, fuel, user_id):
    self.car_id = car_id 
    self.distance = distance
    self.fuel = fuel
    self.user_id = user_id

# Login-Manager - ladet Benutzer aus Datenbank
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Registrierungs-Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        errors = []

        # Validierung der Felder
        if not username:
            errors.append('Benutzername ist erforderlich.')
        if not password:
            errors.append('Passwort ist erforderlich.')
        else:
            if len(password) < 10:
                errors.append('Das gewählte Passwort ist zu kurz. Mind. 10 Zeichen')
                
        if not errors:
            # Überprüfen, ob der Benutzername bereits existiert
            existing_user = User.query.filter_by(username=username).first()

            if existing_user:
                flash('Benutzername ist bereits vergeben!', 'danger')
            else:
                # Passwort hashen
                hashed_password = generate_password_hash(password)

                # Neuen Benutzer erstellen und in die Datenbank einfügen
                new_user = User(username=username, password=hashed_password)
                db.session.add(new_user)
                db.session.commit()

                flash('Registrierung erfolgreich! Du kannst dich nun einloggen.', 'success')
                return redirect(url_for('login'))
            return render_template('register.html')
        else:
            for error in errors:
                flash(error, 'danger')
    return render_template('register.html')

# Login-Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Überprüfen, ob der 'remember me' Haken gesetzt wurde
        remember_me = request.form.get('remember') == 'on'  # Wenn das Häkchen gesetzt ist, wird remember_me auf True gesetzt
        
        try:
            # Verwende Flask-SQLAlchemy-Abfrage für die Benutzerabfrage
            user = User.query.filter_by(username=username).first()

            if user and check_password_hash(user.password, password):  # Passwort überprüfen
                # Wenn die Anmeldedaten korrekt sind, wird der Benutzer eingeloggt
                login_user(user, remember=remember_me)  # 'user' ist ein User-Objekt, keine manuelle Erstellung notwendig
                flash('Erfolgreich eingeloggt!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Benutzername oder Passwort ist ungültig, bitte versuche es erneut.', 'danger')
        except Exception as e:
            flash(f"Fehler bei der Anmeldung: {str(e)}", 'danger')
            app.logger.error(f"Fehler bei der Anmeldung: {str(e)}")  # Fehler loggen

    return render_template('login.html')

# Logout-Route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Erfolgreich abgemeldet!', 'info')
    return redirect(url_for('login'))


# Route für die Homepage
@app.route("/", methods=['GET', 'POST'])
@login_required
def home():
    user = current_user.username

    # Alle Fahrzeuge des eingeloggten Benutzers abrufen
    cars = Car.query.filter_by(user_id=current_user.id).all()
    car_names = list(set(car.car_name for car in cars))  # Duplikate entfernen mit set

    if request.method == 'POST':
        car_name = request.form['car_name']
        distance_str = request.form['distance']
        fuel_str = request.form['fuel']
        errors = []

        # Validierung der Felder
        if not car_name:
            errors.append('Fahrzeugname ist erforderlich.')
        if not distance_str:
            errors.append('Zurückgelegte Kilometer sind erforderlich.')
        else:
            try:
                distance = int(distance_str)
                if not (1 <= distance <= 9999):
                    errors.append('Zurückgelegte Kilometer müssen zwischen 1 und 9999 liegen.')
            except ValueError:
                errors.append('Zurückgelegte Kilometer müssen eine Ganzzahl sein.')
        if not fuel_str:
            errors.append('Getanktes Volumen ist erforderlich.')
        else:
            try:
                fuel = float(fuel_str)
                if not (0.01 <= fuel <= 9999.99):
                    errors.append('Getanktes Volumen muss zwischen 0,01 und 9999,99 Litern liegen.')
            except ValueError:
                errors.append('Getanktes Volumen muss eine Zahl sein.')

        if not errors:
            # Überprüfen, ob "Anderes Fahrzeug" ausgewählt wurde
            if car_name == 'other':
                car_name = request.form['new_car_name']

            # Überprüfen, ob das Auto bereits existiert
            existing_car = Car.query.filter_by(car_name=car_name, user_id=current_user.id).first()

            if existing_car:
                car_id = existing_car.id
            else:
                # Neues Auto erstellen, wenn es nicht existiert
                new_car = Car(car_name=car_name, user_id=current_user.id)
                db.session.add(new_car)
                db.session.commit()
                car_id = new_car.id

            # Neuer FuelLog-Eintrag erstellen
            new_entry = CarFuelLog(car_id=car_id, distance=distance, fuel=fuel, user_id=current_user.id)
            db.session.add(new_entry)
            db.session.commit()

            return redirect(url_for('home'))  # Seite neu laden, nach hinzugefügtem Eintrag
        else:
            for error in errors:
                flash(error, 'danger')

    # Alle Fahrzeuge und zugehörigen Fuellogs des Benutzers abrufen
    fuel_logs = CarFuelLog.query.filter_by(user_id=current_user.id).all()
    car_summary = {}

    # Fahrzeugdaten zusammenstellen
    for log in fuel_logs:
        car_name = log.car.car_name 
        if car_name not in car_summary:
            car_summary[car_name] = {'distance': 0, 'fuel': 0}
        car_summary[car_name]['distance'] += log.distance
        car_summary[car_name]['fuel'] += log.fuel

    # Durchschnittsverbrauch berechnen
    for car in car_summary:
        car_summary[car]['average_consumption'] = (car_summary[car]['fuel'] / car_summary[car]['distance']) * 100

    return render_template('index.html', name=current_user.username, car_summary=car_summary, car_names=car_names)


# Route zum Löschen eines Fahrzeugs via GUI
@app.route('/delete_car/<car_name>', methods=['POST'])
@login_required
def delete_car(car_name):
    # Suche das Fahrzeug des aktuellen Benutzers in der Car-Tabelle
    car = Car.query.filter_by(car_name=car_name, user_id=current_user.id).first()

    if not car:
        flash(f'Fahrzeug "{car_name}" wurde nicht gefunden.', 'danger')
        return redirect(url_for('home'))

    # Lösche alle FuelLog-Einträge, die mit dem Fahrzeug verknüpft sind
    CarFuelLog.query.filter_by(car_id=car.id).delete()

    # Lösche das Fahrzeug selbst
    db.session.delete(car)
    db.session.commit()

    flash(f'Fahrzeug "{car_name}" wurde gelöscht.', 'success')
    return redirect(url_for('home'))




## API
# Middleware zur Überprüfung des JWTs
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            # Extrahiere das Token, indem du 'Bearer ' entfernst
            auth_header = request.headers['Authorization']
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]  # Token nach 'Bearer ' extrahieren

        if not token:
            return jsonify({'message': 'Token fehlt!'}), 403

        try:
            # Versuche, das Token zu decodieren
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['id']).first()
            if not current_user:
                raise Exception("User not found")
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token abgelaufen!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Ungültiges Token!', 'token': token}), 403
        except Exception as e:
            return jsonify({'message': str(e)}), 403

        return f(current_user, *args, **kwargs)
    return decorated_function


# Route für das Benutzer-Login (API)
@app.route('/api/login', methods=['POST'])
@csrf.exempt  # CSRF-Schutz für diese Route deaktivieren
def api_login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Benutzername und Passwort erforderlich'}), 400

    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        try:
            token = jwt.encode({'id': user.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=10)},
                app.config['SECRET_KEY'], algorithm="HS256")
        except Exception as e:
            return jsonify({'message': 'Fehler bei der Token-Erstellung'}), 500
        return jsonify({'token': token})
    return jsonify({'message': 'Benutzername oder Passwort falsch'}), 401


# API zum Abrufen von Fahrzeugen, Gesamtverbrauch, Durchschnittsverbrauch und Distanz pro Benutzer
@app.route('/api/car_stats', methods=['GET'])
@csrf.exempt  # CSRF-Schutz für diese Route deaktivieren
@token_required  # Sicherstellen, dass der Benutzer authentifiziert ist
def get_car_stats(current_user):
    # Den 'name' Parameter aus der URL-Abfrage erhalten (optional)
    car_name_filter = request.args.get('name')  # Beispiel: /api/car_stats?name=Tesla
    try:
        # Fahrzeuge des Benutzers optional nach Namen filtern
        if car_name_filter:
            car = Car.query.filter_by(car_name=car_name_filter, user_id=current_user.id).first()
            if not car:
                return jsonify({'message': 'Fahrzeug nicht gefunden oder kein Zugriff!'}), 404
            car_logs = CarFuelLog.query.filter_by(car_id=car.id).all()
        else:
            # Alle Fahrzeuge und deren Logs des aktuellen Benutzers abrufen
            cars = Car.query.filter_by(user_id=current_user.id).all()
            car_logs = CarFuelLog.query.filter(CarFuelLog.car_id.in_([car.id for car in cars])).all()

        # Fahrzeugstatistiken berechnen
        car_summary = {}
        for log in car_logs:
            car_name = log.car.car_name  # Über die Beziehung auf den Fahrzeugnamen zugreifen
            if car_name not in car_summary:
                car_summary[car_name] = {'distance': 0, 'fuel': 0}
            car_summary[car_name]['distance'] += log.distance
            car_summary[car_name]['fuel'] += log.fuel

        # Durchschnittlichen Kraftstoffverbrauch berechnen
        for car in car_summary:
            if car_summary[car]['distance'] > 0:
                car_summary[car]['average_consumption'] = (car_summary[car]['fuel'] / car_summary[car]['distance']) * 100
            else:
                car_summary[car]['average_consumption'] = 0

        # Rückgabe der Fahrzeugstatistiken
        return jsonify({'car_stats': car_summary}), 200

    except Exception as e:
        return jsonify({'message': f'Fehler beim Abrufen der Fahrzeugstatistiken: {str(e)}'}), 500


# API zum Abrufen von Verbrauchsdaten des Benutzers
@app.route('/api/car_fuel_logs', methods=['GET'])
@csrf.exempt  # CSRF-Schutz für diese Route deaktivieren
@token_required  # Stelle sicher, dass der Benutzer authentifiziert ist
def get_car_fuel_logs(current_user):
    # Hole alle Verbrauchsdaten des aktuellen Benutzers
    car_logs = CarFuelLog.query.filter_by(user_id=current_user.id).all()

    # Bereite die Daten vor, die an den Benutzer zurückgegeben werden
    logs = []
    for log in car_logs:
        logs.append({
            'car_name': log.car.car_name,  # Autoname aus der Car-Tabelle über die Beziehung abrufen
            'distance': log.distance,
            'fuel': log.fuel,
            'date': log.date.strftime('%Y-%m-%d %H:%M:%S')  # Formatiere das Datum
        })

    return jsonify({'car_fuel_logs': logs}), 200


# API zum hinzufügen & löschen von Spritlogs
@app.route('/api/car', methods=['POST','DELETE'])
@csrf.exempt  # CSRF-Schutz für diese Route deaktivieren
@token_required  # Sicherstellen, dass der Benutzer authentifiziert ist
def add_and_delete_spritlogs(current_user):
    if request.method == 'DELETE':
        # Den 'name' Parameter aus der URL-Abfrage erhalten (optional)
        car_name_filter = request.args.get('name')  # Beispiel: /api/car_stats?name=Tesla
        try:
            # Fahrzeug des Benutzers mit dem angegebenen Namen finden
            car = Car.query.filter_by(car_name=car_name_filter, user_id=current_user.id).first()
            if not car:
                return jsonify({'message': 'Fahrzeug nicht gefunden oder kein Zugriff!'}), 404
            # Alle zugehörigen CarFuelLog-Einträge löschen
            CarFuelLog.query.filter_by(car_id=car.id).delete()
            
            # Fahrzeug selbst löschen
            db.session.delete(car)
            db.session.commit()
            return jsonify({'message': f'Fahrzeug und alle zugehörigen Einträge erfolgreich gelöscht!'}), 200
        except Exception as e:
            db.session.rollback()  # Rollback bei Fehlern
            return jsonify({'message': f'Fehler beim Löschen des Fahrzeugs: {str(e)}'}), 500

    if request.method == 'POST':
        data = request.get_json()
        # Sicherstellen, dass alle notwendigen Daten übergeben wurden
        if not data or not data.get('car_name') or not data.get('distance') or not data.get('fuel'):
            return jsonify({'message': 'Fahrzeugname, Strecke und Kraftstoff sind erforderlich.'}), 400

        try:
            # Prüfen, ob das Fahrzeug bereits existiert
            car = Car.query.filter_by(car_name=data['car_name'], user_id=current_user.id).first()
            if not car:
                # Neues Fahrzeug in der Car-Tabelle erstellen
                car = Car(car_name=data['car_name'], user_id=current_user.id)
                db.session.add(car)
                db.session.flush()  # Flush, um die car_id für die weitere Nutzung zu erhalten

            # Neuen CarFuelLog-Eintrag erstellen
            new_log = CarFuelLog(
                car_id=car.id,  # Verknüpfung mit der bestehenden oder neuen Car-Tabelle
                distance=data['distance'],
                fuel=data['fuel'],
                user_id=current_user.id  # Zugehörigkeit zum Benutzer sicherstellen
            )

            # Eintrag in die Datenbank speichern
            db.session.add(new_log)
            db.session.commit()

            return jsonify({'message': 'Eintrag erfolgreich hinzugefügt!'}), 201

        except Exception as e:
            db.session.rollback()  # Rollback bei Fehlern
            return jsonify({'message': f'Fehler beim Hinzufügen des Eintrags: {str(e)}'}), 500


# Start der Anwendung
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Erstelle alle Tabellen (falls nicht bereits vorhanden)
        # Run in venv cli - init_db.py
    app.run(debug=True)
