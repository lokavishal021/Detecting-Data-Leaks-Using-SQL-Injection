# Detecting Data Leaks Using SQL Injection

Academic demo project that demonstrates layered defenses against SQL injection and confidentiality protection via per-user AES encryption. The app is a Flask-based sandbox with a small SQLite database and a simulator endpoint to exercise WAF, parameterized-query protections, capability-based access, and AES encryption.

**Contents**
- **app.py**: Flask application and API endpoints
- **database.py**: SQLite helpers and initialization
- **security.py**: WAF / input analysis logic used by the simulator
- **encryption.py**: Per-user AES encryption helpers
- **capability.py**: Generates and validates capability codes
- **templates/**: Frontend SPA (index.html)
- **static/**: Static assets (JS/CSS)
- **test_security.py**: Unit tests using the Flask test client

**Prerequisites**
- Python 3.10+ (3.11 recommended)
- Git (optional, for cloning)

Quick start (Windows)

1. Open a terminal in the project root.
2. Create and activate a virtual environment:

```powershell
python -m venv venv
venv\Scripts\activate
```

3. Install dependencies:

```powershell
pip install -r requirements.txt
```

4. Run the app:

```powershell
python app.py
```

Open the UI at `http://127.0.0.1:5000`.

Environment variables
- `FLASK_SECRET_KEY` — optional: overrides the default session secret.

Running tests

The repository includes `test_security.py` which uses `unittest` and the Flask test client.

Run the tests from the project root:

```powershell
python -m unittest test_security.py
```

Or run all tests discovered by unittest:

```powershell
python -m unittest discover -v
```

Endpoints (quick)
- `POST /api/register` — JSON `{ "username": "...", "password": "..." }`
- `POST /api/login` — JSON `{ "username": "...", "password": "..." }`
- `GET/POST/DELETE /api/vault` — Vault operations (requires login / capability codes for some actions)
- `POST /api/simulate` — Security simulator that exercises WAF, parameterization, decryption, and capability checks

Troubleshooting
- If you see the Flask warning about the development server, that's expected for this demo.
- If the server doesn't start, verify you ran commands from the project root and your virtual environment has the dependencies installed.
- On Windows, long OneDrive paths or spaces don't normally block execution, but make sure the current directory is readable and writable.


License

This repository now contains a MIT license file. Change it if you prefer a different license.
