"""
Database models for BAS Reviewer SaaS
"""
import uuid
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets

db = SQLAlchemy()
ph = PasswordHasher()


def generate_uuid():
    """Generate a UUID string"""
    return str(uuid.uuid4())


class User(UserMixin, db.Model):
    """User account model"""
    __tablename__ = 'users'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    # Password reset
    password_reset_token = db.Column(db.String(255))
    password_reset_expires = db.Column(db.DateTime)

    # Relationships
    team_memberships = db.relationship('TeamMember', back_populates='user', lazy='dynamic', primaryjoin='User.id==TeamMember.user_id')
    owned_teams = db.relationship('Team', back_populates='owner', lazy='dynamic')
    xero_connections = db.relationship('XeroConnection', back_populates='user', lazy='dynamic')
    reviews = db.relationship('Review', back_populates='user', lazy='dynamic')

    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = ph.hash(password)

    def check_password(self, password):
        """Verify password"""
        try:
            ph.verify(self.password_hash, password)
            # Rehash if needed (argon2 updates)
            if ph.check_needs_rehash(self.password_hash):
                self.password_hash = ph.hash(password)
            return True
        except VerifyMismatchError:
            return False

    def is_locked(self):
        """Check if account is locked"""
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def record_failed_login(self):
        """Record failed login attempt"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.locked_until = datetime.utcnow() + timedelta(minutes=15)

    def record_successful_login(self):
        """Record successful login"""
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login = datetime.utcnow()

    def generate_password_reset_token(self):
        """Generate password reset token"""
        self.password_reset_token = secrets.token_urlsafe(32)
        self.password_reset_expires = datetime.utcnow() + timedelta(hours=1)
        return self.password_reset_token

    def verify_reset_token(self, token):
        """Verify password reset token"""
        if not self.password_reset_token or not self.password_reset_expires:
            return False
        if self.password_reset_token != token:
            return False
        if datetime.utcnow() > self.password_reset_expires:
            return False
        return True

    def clear_reset_token(self):
        """Clear password reset token"""
        self.password_reset_token = None
        self.password_reset_expires = None

    def get_teams(self):
        """Get all teams user belongs to"""
        return [tm.team for tm in self.team_memberships.all()]

    def get_primary_team(self):
        """Get user's primary (owned) team"""
        return self.owned_teams.first()

    def __repr__(self):
        return f'<User {self.email}>'


class Team(db.Model):
    """Team/Organization model"""
    __tablename__ = 'teams'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    name = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(255), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    owner_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    max_members = db.Column(db.Integer, default=5)
    subscription_tier = db.Column(db.String(50), default='free')

    # Relationships
    owner = db.relationship('User', back_populates='owned_teams')
    members = db.relationship('TeamMember', back_populates='team', lazy='dynamic', cascade='all, delete-orphan')
    invitations = db.relationship('TeamInvitation', back_populates='team', lazy='dynamic', cascade='all, delete-orphan')
    xero_connections = db.relationship('XeroConnection', back_populates='team', lazy='dynamic')
    reviews = db.relationship('Review', back_populates='team', lazy='dynamic')

    def add_member(self, user, role='member', invited_by=None):
        """Add a member to the team"""
        if self.get_member(user):
            return None  # Already a member
        membership = TeamMember(
            team_id=self.id,
            user_id=user.id,
            role=role,
            invited_by=invited_by.id if invited_by else None
        )
        db.session.add(membership)
        return membership

    def remove_member(self, user):
        """Remove a member from the team"""
        membership = self.get_member(user)
        if membership:
            db.session.delete(membership)
            return True
        return False

    def get_member(self, user):
        """Get membership for a user"""
        return self.members.filter_by(user_id=user.id).first()

    def is_admin(self, user):
        """Check if user is admin of team"""
        membership = self.get_member(user)
        return membership and membership.role == 'admin'

    def member_count(self):
        """Get number of members"""
        return self.members.count()

    @staticmethod
    def generate_slug():
        """Generate unique team slug"""
        return secrets.token_hex(4)

    def __repr__(self):
        return f'<Team {self.name}>'


class TeamMember(db.Model):
    """Team membership model"""
    __tablename__ = 'team_members'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    team_id = db.Column(db.String(36), db.ForeignKey('teams.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    role = db.Column(db.String(50), default='member')  # 'admin' or 'member'
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    invited_by = db.Column(db.String(36), db.ForeignKey('users.id'))

    # Relationships
    team = db.relationship('Team', back_populates='members')
    user = db.relationship('User', back_populates='team_memberships', foreign_keys=[user_id])

    # Unique constraint
    __table_args__ = (db.UniqueConstraint('team_id', 'user_id', name='unique_team_member'),)

    def __repr__(self):
        return f'<TeamMember {self.user_id} in {self.team_id}>'


class TeamInvitation(db.Model):
    """Team invitation model"""
    __tablename__ = 'team_invitations'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    team_id = db.Column(db.String(36), db.ForeignKey('teams.id'), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default='member')
    token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    invited_by = db.Column(db.String(36), db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    accepted_at = db.Column(db.DateTime)

    # Relationships
    team = db.relationship('Team', back_populates='invitations')
    inviter = db.relationship('User', foreign_keys=[invited_by])

    # Unique constraint
    __table_args__ = (db.UniqueConstraint('team_id', 'email', name='unique_team_invitation'),)

    @staticmethod
    def generate_token():
        """Generate invitation token"""
        return secrets.token_urlsafe(32)

    def is_expired(self):
        """Check if invitation is expired"""
        return datetime.utcnow() > self.expires_at

    def is_valid(self):
        """Check if invitation is valid"""
        return not self.is_expired() and not self.accepted_at

    def accept(self, user):
        """Accept invitation"""
        if not self.is_valid():
            return False
        self.accepted_at = datetime.utcnow()
        self.team.add_member(user, role=self.role, invited_by=self.inviter)
        return True

    def __repr__(self):
        return f'<TeamInvitation {self.email} to {self.team_id}>'


class XeroConnection(db.Model):
    """Xero OAuth connection model"""
    __tablename__ = 'xero_connections'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    team_id = db.Column(db.String(36), db.ForeignKey('teams.id'), nullable=False)
    tenant_id = db.Column(db.String(255), nullable=False)
    tenant_name = db.Column(db.String(255))
    access_token = db.Column(db.Text)
    refresh_token = db.Column(db.Text)
    token_expires_at = db.Column(db.DateTime)
    connected_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

    # Relationships
    user = db.relationship('User', back_populates='xero_connections')
    team = db.relationship('Team', back_populates='xero_connections')

    # Unique constraint
    __table_args__ = (db.UniqueConstraint('team_id', 'tenant_id', name='unique_team_tenant'),)

    def is_token_expired(self):
        """Check if access token is expired"""
        if not self.token_expires_at:
            return True
        return datetime.utcnow() > self.token_expires_at

    def update_tokens(self, access_token, refresh_token, expires_in):
        """Update OAuth tokens"""
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        self.last_used = datetime.utcnow()

    def __repr__(self):
        return f'<XeroConnection {self.tenant_name}>'


class Review(db.Model):
    """BAS Review history model"""
    __tablename__ = 'reviews'

    id = db.Column(db.String(36), primary_key=True, default=generate_uuid)
    team_id = db.Column(db.String(36), db.ForeignKey('teams.id'), nullable=False)
    user_id = db.Column(db.String(36), db.ForeignKey('users.id'))
    xero_connection_id = db.Column(db.String(36), db.ForeignKey('xero_connections.id'))
    company_name = db.Column(db.String(255))
    review_date = db.Column(db.DateTime, default=datetime.utcnow)
    period_start = db.Column(db.Date)
    period_end = db.Column(db.Date)
    total_transactions = db.Column(db.Integer, default=0)
    flagged_count = db.Column(db.Integer, default=0)
    source = db.Column(db.String(50))  # 'upload' or 'xero_api'
    status = db.Column(db.String(50), default='completed')
    file_name = db.Column(db.String(255))
    report_data = db.Column(db.JSON)  # Store flagged items as JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    team = db.relationship('Team', back_populates='reviews')
    user = db.relationship('User', back_populates='reviews')
    xero_connection = db.relationship('XeroConnection')

    def __repr__(self):
        return f'<Review {self.company_name} {self.review_date}>'


# Initialize database tables
def init_db(app):
    """Initialize database with app context"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
