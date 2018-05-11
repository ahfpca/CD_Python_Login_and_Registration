from flask import Flask, render_template, redirect, request, session, flash
from datetime import datetime
from mysqlconnection import MySQLConnection
from flask_bcrypt import Bcrypt
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "sdkjgbw3948th49"

email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
date_reg_exp = re.compile('\d{4}-\d{2}-\d{2}')

mysql = MySQLConnection('login_Reg_DB')


@app.route("/", methods=["get"])
def index():
    if "user_uniq" in session:
        return redirect("/success")

    return render_template("login.html")


@app.route("/logout", methods=["post"])
def logout():
    session.clear()
    return redirect("/")


@app.route("/success")
def success():
    if "user_uniq" in session:
        hashed_uniq_id = session["user_uniq"]
        #print("\n", "%" * 40)

        data = { "hashed_uniq_id": hashed_uniq_id }
        sqlCmd = "SELECT CONCAT_WS(' ', first_name, last_name) AS user_name FROM users WHERE user_uniq = %(hashed_uniq_id)s;"
        result = mysql.query_db(sqlCmd, data)

        #print("result: ", result)
        if result:
            return render_template("success.html", user = result[0])

    return redirect("/")


@app.route("/login", methods=["post"])
def login():
    if "user_uniq" in session:
        return redirect("/success")

    sqlQry = "SELECT * FROM users WHERE email = %(email)s"
    data = { "email": request.form["email"] }
    result = mysql.query_db(sqlQry, data)

    if result:
        if bcrypt.check_password_hash(result[0]['passcode'], request.form['passcode']):
            session.clear()
            session["user_uniq"] = result[0]["user_uniq"]
            flash("Welcome back!", "message")
            return redirect("/success")
        else:
            session["email_login"] = request.form["email"]
            flash("You can not login to the website!", "error")
            return redirect("/")
    else:
        sendError("You can not login to the website!", "error")
        return redirect("/")


@app.route("/register", methods=["post"])
def register():
    if "user_uniq" in session:
        return redirect("/success")

    canSave = True

    # Validate first_name
    first_name = request.form["first_name"].strip()
    #print(f"[{first_name}]")
    if len(first_name) < 1:
        sendError("First name is required!", "first_name")
        canSave = False
    elif len(first_name) < 2:
        sendError("First name should have at least 2 characters!", "first_name")
        canSave = False
    if not charCheckName(first_name):
        sendError("First name accept only alhpabeth and space!", "first_name")
        canSave = False
        
    # Validate last_name
    last_name = request.form["last_name"].strip()
    #print(f"[{last_name}]")
    if len(last_name) < 1:
        sendError("Last name is required!", "last_name")
        canSave = False
    elif len(last_name) < 2:
        sendError("Last name should have at least 2 characters!", "last_name")
        canSave = False
    if not charCheckName(last_name):
        sendError("Last name accept only alhpabeth and space!", "last_name")
        canSave = False
        
    # Validate email
    email = request.form["email"].strip()
    #print(f"[{email}]")
    if len(email) < 1:
        sendError("Email is required!", "email")
        canSave = False
    elif not email_regex.match(request.form["email"]):
        sendError("Email is not valid!", "email")
        canSave = False

    # Validate password
    passcode = request.form["passcode"]
    #print(f"[{passcode}]")
    if len(passcode) < 8:
        sendError("Password should be 8 to 20 characters!", "passcode")
        canSave = False
    elif not charCheckPassword(passcode):
        sendError("Password should contain at least 1 upper case, 1 lower case, 1 number, and 1 special character!", "passcode")
        canSave = False
        
    # Validate confirm password
    pass_confirm = request.form["pass_confirm"]
    if passcode != pass_confirm:
        sendError("Password and its confirm are not matching!", "pass_confirm")
        canSave = False

    # Validate Birth date
    birth_date = request.form["birth_date"].strip()
    #print(f"[{birth_date}]")
    if len(birth_date) < 1:
        sendError("Birth date is required!", "birth_date")
        canSave = False
    elif not date_reg_exp.match(birth_date):
        sendError("Birth date is incorrect!", "birth_date")
        canSave = False
    else:
        try:
            brdate = datetime.strptime(birth_date, '%Y-%m-%d')

            curYear = datetime.now().year
            curMonth = datetime.now().month
            
            birthYear = brdate.year
            birthMonth = brdate.month

            ageLimit = 12

            if curYear < birthYear + ageLimit or (curYear == birthYear + ageLimit and curMonth < birthMonth):
                sendError(f"You should be at least {ageLimit} years old to register.", "birth_date")
                canSave = False
        except:
            sendError("Birth date is incorrect!", "birth_date")
            canSave = False

    # Check for email uniqueness
    sqlQry = "SELECT email FROM users WHERE email = %(email)s;"    
    data = { "email": email }

    res = mysql.query_db(sqlQry, data)
    # print("=" * 80)
    # print(res)

    if len(res) > 0:
        sendError("This Email is already registered in our database!", "email")
        canSave = False

    #debugPrint()
 
    if canSave:
        # Save To Table
        sqlCmd = "INSERT INTO users (first_name, last_name, email, passcode, birth_date, created_at, updated_at) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(passcode)s, %(birth_date)s, NOW(), NOW());"

        hashed_pass = bcrypt.generate_password_hash(passcode)

        data = { "first_name": first_name,
                 "last_name": last_name,
                 "email": email,
                 "passcode": hashed_pass,
                 "birth_date": birth_date }

        new_user_id = mysql.query_db(sqlCmd, data)
        # If user created successfully
        if new_user_id > 0:
            # Create user's uniq id
            result = mysql.query_db(f"SELECT created_at FROM users WHERE user_id = { new_user_id };")
            uniq_id = str(new_user_id) + "_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")

            hashed_uniq_id = bcrypt.generate_password_hash(uniq_id)
            
            # print("$" * 80)
            # print("uniq_id: ", uniq_id)
            # print("hashed_uniq_id: ", hashed_uniq_id)

            data = { "new_user_id": new_user_id,
                     "hashed_uniq_id": hashed_uniq_id }
            sqlCmd = "UPDATE users SET user_uniq = %(hashed_uniq_id)s WHERE user_id = %(new_user_id)s;"
            res = mysql.query_db(sqlCmd, data)

            session.clear()
            session["user_uniq"] = hashed_uniq_id
            flash("You registration was successfull!", "message")
            return redirect("/success")
        else:
            sendError("Something went wrong and while registering your information!", "error")
            return redirect("/")
    else:
        return redirect("/")


def sendError(message, fieldname, route = "/"):
    flash(message, fieldname)
    session["first_name"] = request.form["first_name"]
    session["last_name"] = request.form["last_name"]
    session["email"] = request.form["email"]
    session["birth_date"] = request.form["birth_date"]
    return


def charCheckName(name):
    for c in name:
        if not c.isalpha() and not c.isspace():
            return False

    return True


def charCheckPassword(pwd):
    result = True
    upper = 0
    lower = 0
    number = 0
    nonalphanum = 0

    for c in pwd:
        if c.isupper():
            upper += 1
        if c.islower():
            lower += 1
        if c.isnumeric():
            number += 1
        if not c.isspace() and not c.isalnum():
            nonalphanum += 1

    if upper == 0 or lower == 0 or number == 0 or nonalphanum == 0:
        return False

    return result


def trim(str):
    if len(str) < 1:
        return ""

    if len(str) == 1 and str == " ":
        return ""

    bgn = 0
    while str[bgn] == " " and bgn < len(str) - 1:
        bgn += 1

    end = len(str) - 1
    while str[end] == " " and end > 0:
        end -= 1

    retStr = ""
    for i in range(bgn, end + 1):
        retStr += str[i]

    return retStr


def debugPrint():
    print("\n\n")
    print("=" * 80)
    print(session)
    print(request.form)


if __name__ == "__main__":
    app.run(debug = True)
