# Cyber Recon Dashboard (ReconOps)

A powerful, Flask-based web dashboard designed to assist in cybersecurity and network reconnaissance operations. The dashboard provides an easy-to-use, unified interface for a variety of essential discovery and verification tools.

## Features

- **Robust Authentication**: Secure user registration and login functionality to ensure only authorized operators can access the dashboard.
- **Port Scanner**: Identify open ports and active services on target IP addresses quickly using multi-threaded probes.
- **Network Scanner**: Discover live hosts within a specified local subnet via high-speed, multi-threaded ICMP ping sweeps.
- **Subdomain Finder**: Harness certificate transparency logs (crt.sh) to quickly discover valid subdomains for a target domain.
- **IP Geolocation**: Resolve IP addresses to approximate geographical locations and fetch internet provider context.
- **Password Strength Checker**: Analyze password complexity based on length, alphanumeric mix, and casing.
- **Hash Generator**: Create secure, 256-bit cryptographic hashes (SHA-256) seamlessly from the UI.
- **Export Capabilities**: Easily download your network scan logs directly as local `.txt` files.

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone <your-repository-url>
   cd "Cyber recon Dashboard"
   ```

2. **Install Python dependencies:**
   Ensure you have Python 3 installed. Install the requirements via pip:
   ```bash
   pip install -r requirements.txt
   ```

3. **Initialize the App Server:**
   Start the application. The system will automatically construct the required local SQLite datastore (`dashboard.db`) if it doesn't already exist.
   ```bash
   python app.py
   ```

4. **Access the ReconOps Dashboard:**
   Open your browser and navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000/). If it's your first time, proceed to register an account right from the login prompt.

## Technology Stack

- **Backend Framework:** Python Flask
- **Frontend Framework:** Vanilla CSS (Glassmorphism design language), HTML, Inter Google Font
- **Icons:** FontAwesome
- **Database:** SQLite (managed via SQLAlchemy)
- **Session Auth:** Flask-Login

## Documentation Note

This toolkit is designed purely for informational, defensive, and authorized assessment operations. Unauthorized execution against foreign networks or servers without expressed permission is strictly prohibited. Use responsibly.
