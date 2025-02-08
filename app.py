from flask import Flask, render_template, request, redirect, url_for, flash, Response, Blueprint
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from flask_bcrypt import Bcrypt
import stripe
import os
import matplotlib.pyplot as plt
import io
import base64
from collections import defaultdict
import secrets

# Initialize Flask app
app = Flask(__name__)

# Configurations
from config import Config
app.config.from_object(Config)

# Initialize Extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)
mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Stripe Configuration
stripe.api_key = app.config['STRIPE_SECRET_KEY']

# NFL Teams List
NFL_TEAMS = [
    "Arizona Cardinals", "Atlanta Falcons", "Baltimore Ravens", "Buffalo Bills",
    "Carolina Panthers", "Chicago Bears", "Cincinnati Bengals", "Cleveland Browns",
    "Dallas Cowboys", "Denver Broncos", "Detroit Lions", "Green Bay Packers",
    "Houston Texans", "Indianapolis Colts", "Jacksonville Jaguars", "Kansas City Chiefs",
    "Las Vegas Raiders", "Los Angeles Chargers", "Los Angeles Rams", "Miami Dolphins",
    "Minnesota Vikings", "New England Patriots", "New Orleans Saints", "New York Giants",
    "New York Jets", "Philadelphia Eagles", "Pittsburgh Steelers", "San Francisco 49ers",
    "Seattle Seahawks", "Tampa Bay Buccaneers", "Tennessee Titans", "Washington Commanders"
]

# User Model
class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    is_paid = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    license_key = db.Column(db.String(100), unique=True, nullable=True)

# Game Result Model
class GameResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    year = db.Column(db.Integer, nullable=False)
    week = db.Column(db.String(50), nullable=False)
    team1 = db.Column(db.String(50), nullable=False)
    team1_score = db.Column(db.Integer, nullable=False)
    team2 = db.Column(db.String(50), nullable=False)
    team2_score = db.Column(db.Integer, nullable=False)
    home_team = db.Column(db.String(50), nullable=False)

# Future Game Model
class FutureGame(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    week = db.Column(db.String(50), nullable=False)
    team1 = db.Column(db.String(50), nullable=False)
    team2 = db.Column(db.String(50), nullable=False)

# User Loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Madden Blueprint
madden = Blueprint('madden', __name__)

# Betting Spread Suggestions Logic Added

@madden.route('/home', methods=['GET', 'POST'])
@login_required
def madden_home():
     # Restrict access to users without a license key unless they are admins
    if not current_user.is_admin and not current_user.license_key:
        flash("Access Denied: You need a valid license key to use the Madden Spread Generator.", "danger")
        return redirect(url_for('pricing'))

    if request.method == 'POST':
        year = request.form.get('year')
        week = request.form.get('week')
        home_team = request.form.get('home_team')
        team1 = request.form.get('team1')
        team1_score = int(request.form.get('team1_score'))
        team2 = request.form.get('team2')
        team2_score = int(request.form.get('team2_score'))

        new_game = GameResult(
            user_id=current_user.id,
            year=year,
            week=week,
            home_team=home_team,
            team1=team1,
            team1_score=team1_score,
            team2=team2,
            team2_score=team2_score
        )
        db.session.add(new_game)
        db.session.commit()

        flash('Game added successfully!', 'success')
        return redirect(url_for('madden.madden_home'))

    # Retrieve past games and future games from the database
    games = GameResult.query.filter_by(user_id=current_user.id).all()
    future_games = FutureGame.query.all()

    # Calculate Win/Loss Records
    team_stats = {team: {'wins': 0, 'losses': 0} for team in NFL_TEAMS}
    matchup_stats = defaultdict(list)

    for game in games:
        if game.team1_score > game.team2_score:
            team_stats[game.team1]['wins'] += 1
            team_stats[game.team2]['losses'] += 1
        elif game.team2_score > game.team1_score:
            team_stats[game.team2]['wins'] += 1
            team_stats[game.team1]['losses'] += 1

        # Store point differentials for spread calculations
        matchup_key = tuple(sorted([game.team1, game.team2]))
        point_diff = abs(game.team1_score - game.team2_score)
        matchup_stats[matchup_key].append(point_diff)

    # Generate Win/Loss Chart
    teams = [team for team in NFL_TEAMS if team_stats[team]['wins'] > 0 or team_stats[team]['losses'] > 0]
    wins = [team_stats[team]['wins'] for team in teams]
    losses = [team_stats[team]['losses'] for team in teams]

    fig, ax = plt.subplots()
    ax.barh(teams, wins, color='green', label='Wins')
    ax.barh(teams, losses, left=wins, color='red', label='Losses')
    ax.set_xlabel('Games')
    ax.set_title('Win/Loss Records')
    ax.legend()

    # Save Plot to StringIO
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    buf.seek(0)
    plot_url = base64.b64encode(buf.getvalue()).decode('utf8')
    buf.close()

    # Generate Betting Spread Suggestions for Historical Games
    spreads = []
    for team1 in NFL_TEAMS:
        for team2 in NFL_TEAMS:
            if team1 != team2:
                matchup_key = tuple(sorted([team1, team2]))
                if matchup_stats[matchup_key]:
                    avg_spread = sum(matchup_stats[matchup_key]) / len(matchup_stats[matchup_key])
                    confidence = min(100, len(matchup_stats[matchup_key]) * 10)
                    spreads.append({
                        'team1': team1,
                        'team2': team2,
                        'suggested_spread': f"{avg_spread:.1f} points",
                        'confidence': confidence
                    })

    # Predict Spreads for Future Games
    future_spreads = []
    for game in future_games:
        matchup_key = tuple(sorted([game.team1, game.team2]))
        if matchup_stats[matchup_key]:
            avg_spread = sum(matchup_stats[matchup_key]) / len(matchup_stats[matchup_key])
            confidence = min(100, len(matchup_stats[matchup_key]) * 10)
            future_spreads.append({
                'week': game.week,
                'team1': game.team1,
                'team2': game.team2,
                'predicted_spread': f"{avg_spread:.1f} points",
                'confidence': confidence
            })
        else:
            # If no historical data, provide a placeholder
            future_spreads.append({
                'week': game.week,
                'team1': game.team1,
                'team2': game.team2,
                'predicted_spread': "No data available",
                'confidence': 0
            })

    return render_template('madden_home.html', games=games, nfl_teams=NFL_TEAMS, spreads=spreads, future_spreads=future_spreads, plot_url=plot_url)

@madden.route('/add-future-game', methods=['POST'])
@login_required
def add_future_game():
    week = request.form['week']
    team1 = request.form['team1']
    team2 = request.form['team2']

    new_future_game = FutureGame(week=week, team1=team1, team2=team2)
    db.session.add(new_future_game)
    db.session.commit()

    flash('Future game added successfully!', 'success')
    return redirect(url_for('madden.madden_home'))

@madden.route('/delete-game/<int:game_id>', methods=['POST'])
@login_required
def delete_game(game_id):
    game = GameResult.query.get_or_404(game_id)
    if game.user_id != current_user.id:
        flash("You don't have permission to delete this game.", "danger")
        return redirect(url_for('madden.madden_home'))

    db.session.delete(game)
    db.session.commit()
    flash('Game deleted successfully!', 'success')
    return redirect(url_for('madden.madden_home'))

@madden.route('/export-games')
@login_required
def export_games():
    games = GameResult.query.filter_by(user_id=current_user.id).all()
    output = "Year,Week,Team1,Team1 Score,Team2,Team2 Score,Home Team\n"

    for game in games:
        output += f"{game.year},{game.week},{game.team1},{game.team1_score},{game.team2},{game.team2_score},{game.home_team}\n"

    response = Response(output, mimetype='text/csv')
    response.headers['Content-Disposition'] = 'attachment; filename=game_results.csv'
    return response

# Admin Routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("You do not have access to this page!", "danger")
        return redirect(url_for('dashboard'))

    search_query = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    users = User.query.filter(User.username.contains(search_query)).paginate(page=page, per_page=5)

    return render_template('admin.html', users=users, search_query=search_query)

@app.route('/export')
@login_required
def export_users():
    if not current_user.is_admin:
        flash("You do not have access to this action!", "danger")
        return redirect(url_for('dashboard'))

    users = User.query.all()
    output = "ID,Username,Is_Admin,Is_Paid\n"
    for user in users:
        output += f"{user.id},{user.username},{user.is_admin},{user.is_paid}\n"

    response = Response(output, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=users.csv"
    return response

@app.route('/promote/<int:user_id>')
@login_required
def promote_user(user_id):
    if not current_user.is_admin:
        flash("You do not have access to this action!", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if user:
        user.is_admin = True
        db.session.commit()
        flash(f"{user.username} has been promoted to admin!", "success")

    return redirect(url_for('admin_dashboard'))

@app.route('/delete/<int:user_id>')
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash("You do not have access to this action!", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if user and user.id != current_user.id:
        db.session.delete(user)
        db.session.commit()
        flash(f"{user.username} has been deleted!", "success")

    return redirect(url_for('admin_dashboard'))

@app.route('/create-user', methods=['POST'])
@login_required
def create_user():
    if not current_user.is_admin:
        flash("You do not have access to this action!", "danger")
        return redirect(url_for('dashboard'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    is_admin = 'is_admin' in request.form  # Checkbox to grant admin privileges

    # Check for existing username or email
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        flash('Username or Email already exists.', 'danger')
        return redirect(url_for('admin_dashboard'))

    # Hash the password and create new user
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password, is_admin=is_admin)
    db.session.add(new_user)
    db.session.commit()

    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/generate-license/<int:user_id>')
@login_required
def generate_license(user_id):
    if not current_user.is_admin:
        flash("You do not have access to this action!", "danger")
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if user.license_key:
        flash(f"User {user.username} already has a license key.", "info")
        return redirect(url_for('admin_dashboard'))

    # Generate a unique license key
    license_key = secrets.token_hex(16)
    user.license_key = license_key
    user.is_paid = True  # Automatically mark as paid when license is issued
    db.session.commit()

    flash(f"License key generated for {user.username}: {license_key}", "success")
    return redirect(url_for('admin_dashboard'))

# Placeholder for Payment Integration
@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    flash('Payment processing is not set up yet.', 'info')
    return redirect(url_for('pricing'))

# Password Reset Routes
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = serializer.dumps(user.username, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}\nThis link expires in 15 minutes."
            mail.send(msg)

            flash("A password reset email has been sent!", "info")
            return redirect(url_for('login'))

        flash("User not found!", "danger")

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        username = serializer.loads(token, salt='password-reset', max_age=900)
    except:
        flash("The reset link is invalid or expired.", "danger")
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.commit()

        flash("Your password has been reset!", "success")
        return redirect(url_for('login'))

    return render_template('reset_password.html')

# User Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials, please try again.', 'danger')

    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_paid:
        return redirect(url_for('pricing'))
    return render_template('dashboard.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

app.register_blueprint(madden, url_prefix='/madden')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

