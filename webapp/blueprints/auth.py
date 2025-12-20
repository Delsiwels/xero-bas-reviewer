"""
Authentication Blueprint - Login, Signup, Logout
"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from models import db, User, Team, TeamMember
import uuid

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()

        # Validation
        errors = []
        if not email or '@' not in email:
            errors.append('Please enter a valid email address.')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')
        if not full_name:
            errors.append('Please enter your name.')

        # Check if email exists
        if User.query.filter_by(email=email).first():
            errors.append('An account with this email already exists.')

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/signup.html',
                                   email=email,
                                   full_name=full_name)

        # Create user
        user = User(
            id=str(uuid.uuid4()),
            email=email,
            full_name=full_name
        )
        user.set_password(password)

        # Create personal team
        team = Team(
            id=str(uuid.uuid4()),
            name=f"{full_name}'s Team",
            slug=Team.generate_slug(),
            owner_id=user.id
        )

        db.session.add(user)
        db.session.add(team)
        db.session.flush()

        # Add user as admin of their team
        membership = TeamMember(
            id=str(uuid.uuid4()),
            team_id=team.id,
            user_id=user.id,
            role='admin'
        )
        db.session.add(membership)
        db.session.commit()

        # Log the user in
        login_user(user)
        flash('Welcome! Your account has been created.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('auth/signup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember') == 'on'

        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Invalid email or password.', 'error')
            return render_template('auth/login.html', email=email)

        if user.is_locked():
            flash('Account temporarily locked due to too many failed attempts. Please try again later.', 'error')
            return render_template('auth/login.html', email=email)

        if not user.check_password(password):
            user.record_failed_login()
            db.session.commit()
            flash('Invalid email or password.', 'error')
            return render_template('auth/login.html', email=email)

        # Successful login
        user.record_successful_login()
        db.session.commit()
        login_user(user, remember=remember)

        # Redirect to next page or dashboard
        next_page = request.args.get('next')
        if next_page and next_page.startswith('/'):
            return redirect(next_page)
        return redirect(url_for('dashboard'))

    return render_template('auth/login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Request password reset"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()

        # Always show success message (don't reveal if email exists)
        flash('If an account with that email exists, we have sent a password reset link.', 'info')

        if user:
            token = user.generate_password_reset_token()
            db.session.commit()
            # TODO: Send email with reset link
            # For now, just log the token (remove in production)
            print(f"Password reset token for {email}: {token}")

        return redirect(url_for('auth.login'))

    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Reset password with token"""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    user = User.query.filter_by(password_reset_token=token).first()

    if not user or not user.verify_reset_token(token):
        flash('Invalid or expired reset link. Please request a new one.', 'error')
        return redirect(url_for('auth.forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not password or len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            return render_template('auth/reset_password.html', token=token)

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)

        user.set_password(password)
        user.clear_reset_token()
        db.session.commit()

        flash('Your password has been reset. Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', token=token)
