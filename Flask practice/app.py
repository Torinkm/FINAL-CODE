from flask import Flask, render_template, session, request, redirect, url_for, flash, g
from forms import NameForm, LoginForm
import hashlib
from functools import wraps
from datetime import timedelta, datetime
from wtforms.validators import Email, Length, Regexp
from db_connector import database
import re

db = database()

app = Flask(__name__)
app.config['MESSAGE_FLASHING_OPTIONS'] = {'duration': 5}
app.secret_key = "fortnite"
app.permanent_session_lifetime = timedelta(minutes=2)

@app.before_request
def load_user():
    if "user" in session:
        g.current_user = session.get("user")
    else:
        g.current_user = None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.current_user:
            flash("You need to log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/booking')
def booking():
    return render_template('booking.html',)


@app.route('/health')
def health():
    return render_template('health.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    title = "Registration Page"
    if request.method == "POST":

        user = request.form['nm']
        password = request.form['pword']
        email = request.form['email']

        if not user or len(user) < 3:
            flash("Username must be at least 3 characters long.", "danger")
            return redirect(url_for('register'))
        if not email or not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash("Please provide a valid email address.", "danger")
            return redirect(url_for('register'))
        if not password or len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect(url_for('register'))

        # Hash email and password
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        hashed_email = hashlib.md5(email.encode()).hexdigest()

        # Check if username already exists
        username_exists = db.queryDB("SELECT * FROM users WHERE name = ?", [user])
        if username_exists:
            flash("Username is already taken, please try a different one.", "danger")
            return redirect(url_for('register'))

        # Check if email already exists
        email_exists = db.queryDB("SELECT * FROM users WHERE email = ?", [hashed_email])
        if email_exists:
            flash("Email is already registered, please use a different one.", "danger")
            return redirect(url_for('register'))

        # Insert the new user into the database
        db.updateDB("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [user, hashed_email, hashed_password])
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))
    else:
        return render_template('register.html', title=title)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        # Check if form data is being submitted
        print("POST request received")
        email = request.form.get('email')
        password = request.form.get('password')

        # Check if email and password are present
        if not email or not password:
            flash("Email and password are required.", "danger")
            return redirect(url_for('login'))

        # Hash the email
        hashed_email = hashlib.md5(email.encode()).hexdigest()

        # Hash the password
        hashed_password = hashlib.md5(password.encode()).hexdigest()

        # Check if email and password are being hashed correctly
        print(f"Hashed email: {hashed_email}")
        print(f"Hashed password: {hashed_password}")

        # Query the database for the user with the hashed email
        found_user = db.queryDB("SELECT * FROM users WHERE email = ?", [hashed_email])

        # check if user is found
        print(f"Found user: {found_user}")

        # Check if user is returnedd
        if found_user:
            user_data = found_user[0] 

            # Check if the password matches
            if user_data[2] == hashed_password:
                session['user'] = user_data[1]
                session['email'] = user_data[0] 
                flash("Login successful!", "success")


                print(f"User logged in: {session['user']}")
                print(f"Session data: {session}")

                return redirect(url_for('user'))  # Should redirect here
            else:
                flash("Invalid credentials.", "danger")
        else:
            flash("User not found.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    current_user = session.get('user')
    flash("You have been logged out!", "danger")
    session.pop("user", None)
    session.pop("email", None)
    session.pop("password", None)

    return redirect(url_for("home"))

@app.route("/user")
def user():
    # Make sure the user is logged in
    if 'user' not in session:
        flash("You must be logged in to view this page.", "warning")
        return redirect(url_for('login'))

    title = "User Page"
    current_user = session.get('user')
    return render_template('user.html', title=title, current_user=current_user)

@app.route('/book_details/<int:book_id>')
def book_details(book_id):
    book = db.queryDB("SELECT * FROM Books WHERE book_id = ?", [book_id])
    return render_template('book_details.html', book=book)

@app.route('/data')
def data():
    return render_template('data.html')

@app.route('/delete/<int:book_id>', methods=['get', 'POST'])
def delete(book_id):
    db.updateDB("DELETE FROM Books WHERE book_id = ?", [book_id])
    flash('Book Deleted!!!')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
