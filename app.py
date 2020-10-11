import datetime
import os

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_bootstrap import Bootstrap
from flask_login import (
    LoginManager, UserMixin, current_user, login_required, login_user,
    logout_user)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import (BooleanField, PasswordField, SelectField, StringField,
                     TextAreaField)
from wtforms.fields.html5 import DateField, TimeField
from wtforms.validators import (Email, EqualTo, InputRequired, Length,
                                ValidationError)

app = Flask(__name__)

app.config['SECRET_KEY'] = 'Thisiicwicwfoiqu489!'
app.config['USER_ENABLE_EMAIL'] = False
project_dir = os.path.dirname(os.path.abspath(__file__))
database_file = "sqlite:///{}".format(
    os.path.join(project_dir, "database_file.db"))
app.config['SQLALCHEMY_DATABASE_URI'] = database_file

db = SQLAlchemy(app)
login_manager = LoginManager()
bootstrap = Bootstrap(app)
login_manager.init_app(app)


groups = db.Table('groups',
                  db.Column('group_id', db.Integer, db.ForeignKey(
                      'group.id'), primary_key=True),
                  db.Column('user_id', db.Integer, db.ForeignKey(
                      'user.id'), primary_key=True)
                  )

admins = db.Table('admins',
                  db.Column('group_id', db.Integer, db.ForeignKey(
                      'group.id'), primary_key=True),
                  db.Column('user_id', db.Integer, db.ForeignKey(
                      'user.id'), primary_key=True)
                  )


class User(db.Model, UserMixin):
    """ User Model in the database """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    groups = db.relationship('Group', secondary=groups, lazy='subquery',
                             backref=db.backref('users', lazy=True))
    groups_under = db.relationship('Group', secondary=admins, lazy='subquery',
                                   backref=db.backref('admins', lazy=True))


class Group(db.Model):
    """ Group Model in the Database"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40), unique=True, nullable=False)
    about = db.Column(db.String(80), nullable=False)
    desc = db.Column(db.Text)
    events = db.relationship('Event', backref='owner')


class Event(db.Model):
    """ Event Model in the Database"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    date = db.Column(db.Date, nullable=False)
    start_time = db.Column(db.Time, nullable=False)
    end_time = db.Column(db.Time, nullable=False)
    about = db.Column(db.String(100), nullable=False)
    owner_id = db.Column(db.Integer, db.ForeignKey('group.id'))
    freq = db.Column(db.Integer, default=0)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[
        InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember Me')


def validate_username(username):
    user = User.query.filter_by(username=username.data).first()
    if user is not None:
        raise ValidationError('Please use a different username.')


def validate_email(email):
    user = User.query.filter_by(email=email.data).first()
    if user is not None:
        raise ValidationError('Please use a different email address.')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    username = StringField('Username', validators=[
        InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[
        InputRequired(), Length(min=8, max=80)])
    password2 = PasswordField('Confirm Password', validators=[InputRequired(),
                                                              EqualTo('password',
                                                                      message='Must be equal to above Password')])


def validate_name(name):
    group = Group.query.filter_by(name=name.data).first()
    if group is not None:
        raise ValidationError('Please use a different Group Name.')


class CreateGroupForm(FlaskForm):
    name = StringField('Name', validators=[
        InputRequired(), Length(min=4, max=50)])
    about = StringField('About', validators=[InputRequired(), Length(min=4)])
    description = TextAreaField('Description', validators=[])
    username = StringField('Username', validators=[
        InputRequired(), Length(min=4, max=15)])
    password = PasswordField('Password', validators=[
        InputRequired(), Length(min=8, max=80)])


class AddEventForm(FlaskForm):
    name = StringField('Event Name', validators=[InputRequired()])
    date = DateField('Event Date', validators=[InputRequired()])
    start_time = TimeField('Starting Time', validators=[InputRequired()],
                           render_kw={"placeholder": "(example- 17:00)"})
    end_time = TimeField('Ending Time', validators=[InputRequired()],
                         render_kw={"placeholder": "(example- 21:00)"})
    about = TextAreaField('Short Description about the Event')
    freq = SelectField('Repeat', choices=[('1', "Once"), ('2', "Daily"), (
        '3', "Weekly"), ('4', "Monthly")], validators=[InputRequired()])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/addgroup', methods=['GET', 'POST'], endpoint='addgroup')
def addgroup():
    form = CreateGroupForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                new_group = Group(name=form.name.data, about=form.about.data,
                                  desc=form.description.data)
                user.groups_under.append(new_group)
                db.session.add(new_group)
                db.session.add(user)
                db.session.commit()
                flash('A New Group has been Made', 'success')
                return redirect(url_for('login'))
        flash("Invalid username or Password", 'error')
    return render_template('group_signup.html', form=form)


@app.route('/group-home', endpoint='home')
@login_required
def home():
    print(current_user.groups_under.name)
    return render_template('group-home.html', group=current_user.groups_under)


@app.route('/group-events', endpoint='events')
@login_required
def events():
    group = current_user.aell_groups_under
    print(datetime.datetime.now().date())
    all_events = Event.query.filter_by(
        owner_id=group.id, date=datetime.datetime.now().date()).all()
    print(all_events)
    return render_template('group-events.html', events=all_events)


@app.route('/addevent', methods=['GET', 'POST'])
@login_required
def addevent():
    form = AddEventForm()

    if form.validate_on_submit():
        new_event = Event(name=form.name.data,
                          date=form.date.data,
                          start_time=form.start_time.data,
                          end_time=form.end_time.data,
                          about=form.about.data,
                          owner_id=current_user.groups_under.id,
                          freq=form.freq.data
                          )
        print(new_event.date)
        db.session.add(new_event)
        db.session.commit()
        flash('A New Event has been Created', 'success')
        return redirect(url_for('home'))
    return render_template('addevent.html', form=form)


@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash("Successfully Logged In", 'success')
                return redirect(url_for('dashboard'))
        flash("Invalid username or Password", 'error')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'], endpoint='signup')
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Succesfully Registered', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/calendar', endpoint='calendar', methods=["GET", "POST"])
@login_required
def calendar():
    print(request.__dict__.keys())
    if request.method == "POST":
        date_clk = request.form['data']
    else:
        date_clk = datetime.datetime.now().date()
    print(type(date_clk))
    new_date = datetime.datetime.strptime(
        str(date_clk).strip('"'), '%Y-%m-%d').date()
    all_groups = current_user.groups
    all_events = []
    for ev in all_groups:
        print(ev.name)
        all_events += Event.query.filter_by(owner_id=ev.id,
                                            date=date_clk).all()
    print(all_events)
    return render_template('calendar.html', events=all_events)


@app.route('/dashboard', endpoint='dashboard')
@login_required
def dashboard():
    all_groups = current_user.groups
    all_events = []
    for ev in all_groups:
        all_events += Event.query.filter_by(owner_id=ev.id).all()
    return render_template('dashboard.html', events=all_events,

                           login_user=current_user)


@app.route('/change', methods=['GET', 'POST'], endpoint='select')
@login_required
def select():
    all_groups = Group.query.all()
    if request.method == 'POST':
        for current_group in all_groups:
            if current_group.name in request.form:
                if current_group not in current_user.groups:
                    current_user.groups.append(current_group)
            else:
                if current_group in current_user.groups:
                    current_user.groups.remove(current_group)
        db.session.add(current_user)
        db.session.commit()
        flash('All Changes Made', 'success')

    return render_template('change.html', name=current_user.username,
                           login_user=current_user, available=all_groups)


@app.route('/logout', endpoint='logout')
@login_required
def logout():
    logout_user()
    flash('Successfully Logged Out', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
