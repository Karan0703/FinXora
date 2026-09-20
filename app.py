from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

from urllib.parse import urlparse
import re
import os
from datetime import datetime


# =========================================================
# APP CONFIGURATION
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = "finxora-development-secret-key"

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_PATH = os.path.join(BASE_DIR, "finxora.db")

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + DATABASE_PATH
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# =========================================================
# EXTENSIONS
# =========================================================

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login first."


# =========================================================
# DATABASE MODELS
# =========================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    is_admin = db.Column(
        db.Boolean,
        default=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        nullable=True
    )

    scan_type = db.Column(
        db.String(30),
        nullable=False
    )

    content = db.Column(
        db.Text,
        nullable=False
    )

    risk_score = db.Column(
        db.Integer,
        default=0
    )

    risk_level = db.Column(
        db.String(30),
        nullable=False
    )

    category = db.Column(
        db.String(100),
        nullable=True
    )

    reasons = db.Column(
        db.Text,
        nullable=True
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class ScamReport(db.Model):
    id = db.Column(
        db.Integer,
        primary_key=True
    )

    report_type = db.Column(
        db.String(50),
        nullable=False
    )

    target = db.Column(
        db.String(255),
        nullable=False
    )

    category = db.Column(
        db.String(100),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================================================
# LOGIN MANAGER
# =========================================================

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# =========================================================
# SCAM DETECTION PATTERNS
# =========================================================

SCAM_PATTERNS = {

    "OTP / Account": [
        r"\botp\b",
        r"one time password",
        r"share.*otp",
        r"send.*otp",
        r"verify.*account",
        r"account.*verify"
    ],

    "Banking / Payment": [
        r"bank account",
        r"credit card",
        r"debit card",
        r"upi",
        r"payment",
        r"pay now",
        r"send money",
        r"transfer money",
        r"bank details"
    ],

    "KYC Scam": [
        r"\bkyc\b",
        r"kyc.*update",
        r"kyc.*expire",
        r"pan card",
        r"aadhar",
        r"aadhaar"
    ],
    "Job Scam": [
        r"work from home",
        r"part time job",
        r"earn.*per day",
        r"earn.*daily",
        r"job offer",
        r"registration fee",
        r"joining fee",
        r"salary.*urgent"
    ],

    "Investment Scam": [
        r"guaranteed return",
        r"guaranteed profit",
        r"double.*money",
        r"investment",
        r"crypto",
        r"trading profit",
        r"risk free"
    ],

    "Electricity Scam": [
        r"electricity bill",
        r"power connection",
        r"electricity.*disconnect",
        r"bill.*due",
        r"connection.*cut"
    ],

    "Prize / Lottery Scam": [
        r"you won",
        r"winner",
        r"lottery",
        r"prize",
        r"reward",
        r"cash prize",
        r"claim.*reward"
    ]
}


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url):

    score = 0
    reasons = []

    original_url = url.strip()

    if not original_url:
        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "category": "URL Analysis",
            "reasons": ["No URL provided."]
        }

    test_url = original_url

    if not test_url.startswith(("http://", "https://")):
        test_url = "https://" + test_url

    try:
        parsed = urlparse(test_url)

        hostname = parsed.hostname

        if not hostname:
            return {
                "risk_score": 80,
                "risk_level": "HIGH",
                "category": "Invalid URL",
                "reasons": ["The URL could not be properly identified."]
            }

        hostname = hostname.lower()

        # HTTPS check
        if parsed.scheme != "https":
            score += 15
            reasons.append(
                "The website is not using HTTPS."
            )

        # IP address instead of domain
        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        if re.match(ip_pattern, hostname):
            score += 30
            reasons.append(
                "The link uses an IP address instead of a normal domain."
            )

        # @ symbol
        if "@" in test_url:
            score += 25
            reasons.append(
                "The URL contains an @ symbol, which can be used to disguise the destination."
            )

        # Too many subdomains
        if hostname.count(".") >= 4:
            score += 15
            reasons.append(
                "The domain contains an unusually large number of subdomains."
            )

        # Suspicious keywords
        suspicious_words = [
            "verify",
            "login",
            "secure",
            "account",
            "update",
            "kyc",
            "reward",
            "winner",
            "claim",
            "free",
            "bonus",
            "gift",
            "urgent",
            "payment"
        ]

        found_words = []

        for word in suspicious_words:

            if word in hostname:
                found_words.append(word)

        if found_words:
            score += min(20, len(found_words) * 5)

            reasons.append(
                "Suspicious keywords detected in the domain: "
                + ", ".join(found_words)
            )

        # URL shorteners
        shorteners = [
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "cutt.ly",
            "shorturl.at"
        ]

        if hostname in shorteners:
            score += 20
            reasons.append(
                "The URL uses a shortened-link service."
            )

    except Exception:
        score += 50

        reasons.append(
            "The URL format appears unusual or invalid."
        )

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"
    if not reasons:
        reasons.append(
            "No major suspicious URL indicators were detected."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "category": "URL Analysis",
        "reasons": reasons
    }


# =========================================================
# MESSAGE ANALYSIS
# =========================================================

def detect_message(text):

    score = 0
    reasons = []
    category = "General Suspicious Message"

    text_lower = text.lower()

    for category_name, patterns in SCAM_PATTERNS.items():

        category_found = False

        for pattern in patterns:

            if re.search(pattern, text_lower):

                category_found = True
                score += 20

                reasons.append(
                    f"Possible {category_name} scam indicator detected."
                )

                break

        if category_found and category == "General Suspicious Message":
            category = category_name

    # Urgency / threat detection

    urgent_words = [
        "urgent",
        "immediately",
        "within 24 hours",
        "today",
        "last warning",
        "account will be blocked",
        "account will be suspended",
        "connection will be disconnected"
    ]

    for word in urgent_words:

        if word in text_lower:

            score += 10

            reasons.append(
                "The message uses urgent or threatening language."
            )

            break

    # Link detection

    url_pattern = r"(https?://[^\s]+|www\.[^\s]+)"

    urls = re.findall(
        url_pattern,
        text_lower
    )

    if urls:

        for found_url in urls:

            url_result = analyze_url(found_url)

            score += url_result["risk_score"]

            reasons.extend(
                url_result["reasons"]
            )

        category = "Suspicious Link / Phishing"

    score = min(score, 100)

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    if not reasons:

        reasons.append(
            "No major scam indicators were detected in the message."
        )

    # Remove duplicate reasons

    reasons = list(dict.fromkeys(reasons))

    return {
        "risk_score": score,
        "risk_level": level,
        "category": category,
        "reasons": reasons
    }


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# SCANNER PAGE
# =========================================================

@app.route("/scanner")
def scanner():

    return render_template(
        "scanner.html"
    )


# =========================================================
# SCAN
# =========================================================

@app.route("/scan", methods=["POST"])
def scan():

    scan_type = request.form.get(
        "scan_type",
        "message"
    )

    content = request.form.get(
        "content",
        ""
    ).strip()

    if not content:

        flash(
            "Please enter a message or URL.",
            "error"
        )

        return redirect(
            url_for("scanner")
        )

    if scan_type == "url":

        result = analyze_url(
            content
        )

    else:

        result = detect_message(
            content
        )

    scan_record = Scan(

        user_id=(
            current_user.id
            if current_user.is_authenticated
            else None
        ),

        scan_type=scan_type,

        content=content,

        risk_score=result["risk_score"],

        risk_level=result["risk_level"],

        category=result.get(
            "category",
            "URL Analysis"
        ),

        reasons="|".join(
            result["reasons"]
        )
    )
    db.session.add(
        scan_record
    )

    db.session.commit()

    return render_template(
        "result.html",

        result=result,

        scan_type=scan_type,

        content=content
    )


# =========================================================
# REPORT SCAM
# =========================================================

@app.route(
    "/report",
    methods=["GET", "POST"]
)
def report():

    if request.method == "POST":

        report_type = request.form.get(
            "report_type",
            ""
        ).strip()

        target = request.form.get(
            "target",
            ""
        ).strip()

        category = request.form.get(
            "category",
            ""
        ).strip()

        description = request.form.get(
            "description",
            ""
        ).strip()

        if not report_type or not target or not category or not description:

            flash(
                "Please fill all fields.",
                "error"
            )

            return redirect(
                url_for("report")
            )

        new_report = ScamReport(

            report_type=report_type,

            target=target,

            category=category,

            description=description
        )

        db.session.add(
            new_report
        )

        db.session.commit()

        flash(
            "Thank you. Your scam report has been submitted.",
            "success"
        )

        return redirect(
            url_for("report")
        )

    return render_template(
        "report.html"
    )


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        name = request.form.get(
            "name",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if not name or not email or not password:

            flash(
                "Please fill all fields.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        existing_user = User.query.filter_by(
            email=email
        ).first()

        if existing_user:

            flash(
                "Email is already registered.",
                "error"
            )

            return redirect(
                url_for("register")
            )

        hashed_password = generate_password_hash(
            password
        )

        new_user = User(

            name=name,

            email=email,

            password=hashed_password
        )

        db.session.add(
            new_user
        )

        db.session.commit()

        flash(
            "Registration successful. Please login.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            login_user(user)
            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid email or password.",
            "error"
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
@login_required
def logout():

    logout_user()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("index")
    )


# =========================================================
# USER DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    scans = Scan.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Scan.created_at.desc()
    ).all()

    return render_template(
        "dashboard.html",
        scans=scans
    )


# =========================================================
# ADMIN DASHBOARD
# =========================================================

@app.route("/admin")
@login_required
def admin():

    if not current_user.is_admin:

        flash(
            "Admin access required.",
            "error"
        )

        return redirect(
            url_for("dashboard")
        )

    reports = ScamReport.query.order_by(
        ScamReport.created_at.desc()
    ).all()

    scans = Scan.query.order_by(
        Scan.created_at.desc()
    ).all()

    users = User.query.order_by(
        User.created_at.desc()
    ).all()

    return render_template(
        "admin.html",
        reports=reports,
        scans=scans,
        users=users
    )


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

with app.app_context():

    db.create_all()


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )
