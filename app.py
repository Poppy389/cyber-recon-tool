from flask import Flask, render_template, request, redirect, url_for, flash, Response
import socket
import hashlib
import requests
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import subprocess
import platform
import ipaddress
import concurrent.futures

app = Flask(__name__)
app.config['SECRET_KEY'] = 'highly_secure_recon_key_123!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dashboard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials. Please try again.")
            
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
        
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash("Username already exists.")
        elif len(password) < 6:
            flash("Password must be at least 6 characters.")
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password_hash=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
            
    return render_template("register.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/")
@login_required
def home():
    return render_template("index.html")

@app.route("/portscanner", methods=["GET"])
@login_required
def portscanner():
    return render_template("portscanner.html")

@app.route("/portscanner_stream")
@login_required
def portscanner_stream():
    target = request.args.get('target', '')
    def generate():
        if not target:
            yield "data: DONE\n\n"
            return
        yield f"data: START_{target}\n\n"
        for port in range(1, 1025):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)  # Reduce timeout for faster scanning 1024 ports
            if s.connect_ex((target, port)) == 0:
                yield f"data: {port}\n\n"
            s.close()
        yield "data: DONE\n\n"
    return Response(generate(), mimetype="text/event-stream")

@app.route("/passwordchecker", methods=["GET","POST"])
@login_required
def passwordchecker():
    strength = ""
    if request.method == "POST":
        password = request.form["password"]
        score = 0
        if len(password) >= 8:
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if score <=2:
            strength = "Weak"
        elif score ==3:
            strength = "Moderate"
        else:
            strength = "Strong"
    return render_template("passwordchecker.html", strength=strength)

@app.route("/iplookup", methods=["GET","POST"])
@login_required
def iplookup():
    ip_info = {}
    if request.method == "POST":
        ip = request.form["ip"]
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/").json()
            ip_info = {
                "IP": response.get("ip"),
                "City": response.get("city"),
                "Region": response.get("region"),
                "Country": response.get("country_name"),
                "Org": response.get("org")
            }
        except:
            ip_info = {"Error": "Could not fetch info"}
    return render_template("iplookup.html", ip_info=ip_info)

@app.route("/hashgenerator", methods=["GET","POST"])
@login_required
def hashgenerator():
    hash_result = ""
    if request.method == "POST":
        text = request.form["text"]
        hash_result = hashlib.sha256(text.encode()).hexdigest()
    return render_template("hashgenerator.html", hash_result=hash_result)

@app.route("/subdomain", methods=["GET", "POST"])
@login_required
def subdomain():
    subdomains = []
    error = None
    domain = ""
    if request.method == "POST":
        domain = request.form.get("domain", "").strip()
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name_value = entry.get('name_value', '')
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip()
                        if name and name.endswith(domain):
                            if name.startswith("*."):
                                name = name[2:]
                            if name not in subdomains:
                                subdomains.append(name)
                subdomains.sort()
            else:
                error = f"crt.sh API returned status code {r.status_code}"
        except Exception as e:
            error = f"Failed to fetch data: {str(e)}"
            
    return render_template("subdomain.html", subdomains=subdomains, domain=domain, error=error)

def ping_host(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', '-w', '1000' if platform.system().lower() == 'windows' else '1', str(ip)]
    
    creation_flags = 0x08000000 if platform.system().lower() == 'windows' else 0
    try:
        output = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=creation_flags)
        if output.returncode == 0:
            return str(ip)
    except:
        pass
    return None

@app.route("/networkscanner", methods=["GET", "POST"])
@login_required
def networkscanner():
    live_hosts = []
    error = None
    subnet = ""
    if request.method == "POST":
        subnet = request.form.get("subnet", "").strip()
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            hosts = list(network.hosts())
            if len(hosts) > 1024:
                error = "Subnet too large. Please limit to /22 or smaller."
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                    results = executor.map(ping_host, hosts)
                    live_hosts = [host for host in results if host]
                live_hosts.sort(key=lambda ip: ipaddress.IPv4Address(ip))
        except ValueError:
            error = "Invalid CIDR format. Use format like 192.168.1.0/24"
        except Exception as e:
            error = f"An error occurred: {str(e)}"
            
    return render_template("networkscanner.html", live_hosts=live_hosts, subnet=subnet, error=error)

def init_db():
    with app.app_context():
        db.create_all()

if __name__ == "__main__":
    if not os.path.exists('dashboard.db'):
        init_db()
    app.run(debug=True)