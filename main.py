import os
import time
import requests
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-fallback-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mileage.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    trips = db.relationship('Trip', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Trip(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_location = db.Column(db.Text, nullable=False)
    end_location = db.Column(db.Text, nullable=False)
    distance_miles = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, server_default=db.func.now())


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ---------------------------------------------------------------------------
# Distance calculation: Nominatim geocoding + OSRM routing
# ---------------------------------------------------------------------------

NOMINATIM_URL = 'https://nominatim.openstreetmap.org/search'
OSRM_URL = 'http://router.project-osrm.org/route/v1/driving'
HEADERS = {'User-Agent': 'mileage-tracker/1.0 (joseph.jia23@gmail.com)'}


def geocode(address):
    resp = requests.get(
        NOMINATIM_URL,
        params={'q': address, 'format': 'json', 'limit': 1},
        headers=HEADERS,
        timeout=8
    )
    resp.raise_for_status()
    results = resp.json()
    if not results:
        raise ValueError(f'Could not geocode address: "{address}"')
    return float(results[0]['lat']), float(results[0]['lon'])


def calculate_driving_miles(start_text, end_text):
    start_lat, start_lon = geocode(start_text)
    time.sleep(1)  # Nominatim rate limit: 1 req/s
    end_lat, end_lon = geocode(end_text)

    url = f'{OSRM_URL}/{start_lon},{start_lat};{end_lon},{end_lat}'
    resp = requests.get(url, params={'overview': 'false'}, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    if data.get('code') != 'Ok' or not data.get('routes'):
        raise ValueError('OSRM could not find a driving route between those locations.')
    meters = data['routes'][0]['distance']
    return round(meters / 1609.344, 2)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        if password != confirm:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        if User.query.filter_by(email=email).first():
            flash('An account with that email already exists.', 'danger')
            return render_template('register.html')

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Main app routes
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=current_user.username)


@app.route('/calculate', methods=['POST'])
@login_required
def calculate():
    data = request.get_json()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    if not start or not end:
        return jsonify({'error': 'Both start and end locations are required.'}), 400
    try:
        miles = calculate_driving_miles(start, end)
    except ValueError as e:
        return jsonify({'error': str(e)}), 422
    except Exception:
        return jsonify({'error': 'Failed to calculate distance. Please try again.'}), 500
    return jsonify({'distance_miles': miles, 'start': start, 'end': end})


@app.route('/log', methods=['POST'])
@login_required
def log_trip():
    data = request.get_json()
    start = (data.get('start') or '').strip()
    end = (data.get('end') or '').strip()
    distance_miles = data.get('distance_miles')
    if not start or not end or distance_miles is None:
        return jsonify({'error': 'Missing trip data.'}), 400
    trip = Trip(
        user_id=current_user.id,
        start_location=start,
        end_location=end,
        distance_miles=float(distance_miles)
    )
    db.session.add(trip)
    db.session.commit()
    return jsonify({
        'success': True,
        'trip': {
            'id': trip.id,
            'start': trip.start_location,
            'end': trip.end_location,
            'miles': trip.distance_miles,
            'timestamp': trip.timestamp.strftime('%b %d, %Y %I:%M %p') if trip.timestamp else ''
        }
    })


@app.route('/history')
@login_required
def history():
    trips = Trip.query.filter_by(user_id=current_user.id)\
                      .order_by(Trip.timestamp.desc()).all()
    return jsonify([
        {
            'id': t.id,
            'start': t.start_location,
            'end': t.end_location,
            'miles': t.distance_miles,
            'timestamp': t.timestamp.strftime('%b %d, %Y %I:%M %p') if t.timestamp else ''
        }
        for t in trips
    ])


@app.route('/history/<int:trip_id>', methods=['DELETE'])
@login_required
def delete_trip(trip_id):
    trip = Trip.query.filter_by(id=trip_id, user_id=current_user.id).first()
    if not trip:
        return jsonify({'error': 'Trip not found.'}), 404
    db.session.delete(trip)
    db.session.commit()
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
