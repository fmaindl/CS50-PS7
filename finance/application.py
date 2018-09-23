import os
import cs50
import re
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Ensure environment variable is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    stocks_owned = db.execute("SELECT DISTINCT stock FROM transaction WHERE id = :id;", id=session['user_id'])

    number_of_rows= len(stocks_owned) - 1

    i = 0

    total_value=0

    for stock in stocks_owned:

        stock_list=[]
        stock_list[i]=stock

        value = db.execute("SELECT SUM(total_amount) FROM transaction WHERE id = :id GROUP BY stock HAVING stock=:stock", id=session['usestockr_id'], stock=stocks_owned["stock"])
        value_list=[]
        value_list[i] = value

        amount_owned = db.execute("SELECT SUM(amount) FROM transaction WHERE id = :id GROUP BY stock HAVING stock=:stock", id=session['user_id'], stock = stocks_owned["stock"])
        amount_list=[]
        amount_list[i]= amount_owned

        quote_input = stocks_owned[i]
        quote_info = lookup(quote_input)
        price = quote_info['price']
        price_list=[]
        price_list[i] = price


        total_value+=value

        i+=1

    cash = db.execute("SELECT cash FROM users WHERE id = :id;", id=session['user_id'])

    grand_total = total_value + cash

    ###("SELECT stock, SUM(total_amount) FROM transaction WHERE id = :id;, id=session['user_id'] GROUP BY stock")####


    return render_template("index.html", number_of_rows=number_of_rows, stock_list=stock_list, amount_list=amount_list, value_list=value_list, price_list=price_list, total_value=total_value, grand_total=grand_total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("stock"):
            return apology("must provide stock", 403)

        if not request.form.get("amount"):
            return apology("must provide amount", 403)

        amount = int(request.form.get("amount"))

        if amount <= 0:
            return  apology("must provide a positive value", 403)

        quote_input = request.form.get("quote")
        quote_info = lookup(quote_input)

        if not quote_info:
            return apology("The quote you are looking for is not available", 403)

        symbol = quote_info['symbol']
        price = quote_info['price']

        total_order = float(amount) * float(price)

        cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])

        if total_order > cash:
            return apology("Your funds are insufficient", 403)

        else:
            remaining_cash = cash - total_order

        db.execute("UPDATE users SET cash = remaining_cash WHERE id = :id", id = session["user_id"])

        username = db.execute("SELECT username FROM users WHERE id = :id", id = session["user_id"])

        date = str(datetime.datetime.today()).split()[0]

        time = datetime.datetime.time(datetime.datetime.now())

        db.execute("INSERT INTO transaction (id, username, stock, amount, price, total_amount, date, time) VALUES(:id, :username, :stock, :amount, :price, :total_amount, :date, :time)"
                    , id = session["user_id"], username=username, stock=quote_info['symbol'], amount=amount, price=quote_info['price'], total_order=total_order, date = date, time = time)

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute("SELECT stock, amount, price, date, time, total_amount FROM transactions WHERE id=:id", id=session['user_id'])


    return render_template("index.html", transactions=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""


    if request.method == "POST":

        if not request.form.get("quote"):
            return apology("Please enter a symbol", 403)

        quote_input = request.form.get("quote")
        quote_info = lookup(quote_input)

        if not quote_info:
            return apology("The quote you are looking for is not available", 403)

        symbol = quote_info['symbol']
        price = quote_info['price']
        return render_template("quoted.html", symbol=symbol, price=price)

    elif request.method == "GET":
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    session.clear()

    """Register user"""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure the confirmation was submitted
        elif not request.form.get("confirmation"):
            return apology("must provide the confirmation of the password you entered", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username", username=request.form.get("username"))

        # make sure the username does not already exist
        if len(rows) == 1:
            return apology("The username you have entered already exists", 409)

        # make sure password at least 8 char long
        password = request.form.get("password")
        if len(password) < 8:
            return apology("Please provide a password that is at least 8 characters long", 405)

        # Ensure the password and the confirmation are identical
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("The password and the confirmation do not match", 405)

        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        # the user passed all the steps and can now be registered
        registration = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=request.form.get("username"), hash=hash)



    else:
        return render_template("register.html")

    return redirect("/")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("must provide stock", 403)

        if not request.form.get("amount"):
            return apology("must provide amount", 403)

        amount = int(request.form.get("amount"))

        if amount <= 0:
            return  apology("must provide a positive value", 403)

        quote_input = request.form.get("quote")
        quote_info = lookup(quote_input)

        if not quote_info:
            return apology("The quote you are looking for is not available", 403)

        symbol = quote_info['symbol']
        price = quote_info['price']

        total_sale = float(amount) * float(price)

        cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])

        updated_cash = cash + total_sale

        db.execute("UPDATE users SET cash = remaining_cash WHERE id = :id", id = session["user_id"])

        username = db.execute("SELECT username FROM users WHERE id = :id", id = session["user_id"])

        date = str(datetime.datetime.today()).split()[0]

        time = datetime.datetime.time(datetime.datetime.now())

        db.execute("INSERT INTO transaction (id, username, stock, amount, price, total_amount, date, time) VALUES(:id, :username, :stock, :amount, :price, :total_amount, :date, :time)"
                    , id = session["user_id"], username=username, stock=quote_info['symbol'], amount=amount, price=quote_info['price'], total_amount=total_sale, date = date, time = time)

        return redirect("/")


def errorhandler(e):
    """Handle error"""
    return apology(e.name, e.code)


# listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""

    if request.method == "POST":

        if not request.form.get("password"):
            return apology("must provide password", 403)

        if not request.form.get("confirmation"):
            return apology("must provide confirmation", 403)

        if not request.form.get("new_password"):
            return apology("must provide new password", 403)

        # query database for username
        rows = db.execute("SELECT * FROM users WHERE id = :user_id", user_id=session['user_id'])

        if not pwd_context.verify(request.form.get('password'), rows[0]['hash']):
            return apology("the password you entered is not valid", 403)

        if request.form.get("new_password") != request.form.get("confirmation"):
            return apology("The password and the confirmation passwords do not match", 403)

        password=request.form.get("new_password")

        if len(password) < 8:
            return apology("Please provide a password that is at least 8 characters long", 405)

        hash = generate_password_hash(request.form.get("new_password"), method='pbkdf2:sha256', salt_length=8)

        # the user passed all the steps and can now be registered
        registration = db.execute("UPDATE users (hash) SET hash=:hash", hash=hash)

        return redirect("/")

    else:
        return redirect("/")
