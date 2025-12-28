from flask import Flask, render_template, request, jsonify, session, redirect
import pickle
import base64

app = Flask(__name__)
app.secret_key = "super-secret-key-do-not-share"  # ❌ HARDCODED SECRET

# Database
users = [
    {"id": 1, "email": "admin@example.com", "password": "admin123", "is_admin": True},
    {"id": 2, "email": "user@example.com", "password": "password123", "is_admin": False}
]

products = [
    {"id": 1, "name": "Gaming Laptop", "price": 1299.99, "category": "Laptops", "description": "High performance gaming laptop with RTX 4090", "image": "💻"},
    {"id": 2, "name": "iPhone 15", "price": 999.99, "category": "Phones", "description": "Latest iPhone with A17 Pro chip", "image": "📱"},
    {"id": 3, "name": "iPad Pro", "price": 1299.99, "category": "Tablets", "description": "12.9 inch iPad with M2 chip", "image": "📱"},
    {"id": 4, "name": "MacBook Pro", "price": 2499.99, "category": "Laptops", "description": "M3 Max laptop for professionals", "image": "💻"},
    {"id": 5, "name": "AirPods Pro", "price": 249.99, "category": "Audio", "description": "Active noise cancellation earbuds", "image": "🎧"}
]

comments = {}
cart_items = {}

# ============================================
# HOMEPAGE
# ============================================

@app.route('/')
def index():
    return render_template('index.html', products=products)

# ============================================
# PRODUCTS PAGE
# ============================================

@app.route('/products')
def products_page():
    return render_template('products.html', products=products)

# ============================================
# VULNERABILITY 1: SQL INJECTION
# ============================================

@app.route('/search', methods=['GET', 'POST'])
def search():
    """🚨 SQL INJECTION - User input concatenated into SQL"""
    query = request.args.get('q', '')
    
    # Check if SQL injection attempt
    if "'" in query or "--" in query or ";" in query or "OR" in query.upper():
        return render_template('search.html', 
            results=[], 
            query=query,
            alert={
                "type": "danger",
                "title": "🚨 SQL INJECTION DETECTED!",
                "message": f"Good catch! You found SQL Injection!",
                "explanation": f"Your input was directly concatenated into SQL query: SELECT * FROM products WHERE name LIKE '%{query}%'",
                "impact": "Attacker could: DROP tables, steal all data, delete everything, modify records",
                "lesson": "Use parameterized queries: db.execute('SELECT * FROM products WHERE name LIKE ?', [query])"
            }
        )
    
    # Safe search for valid queries
    results = [p for p in products if query.lower() in p['name'].lower() or query.lower() in p['description'].lower()]
    return render_template('search.html', results=results, query=query)

# ============================================
# PRODUCT DETAIL PAGE
# ============================================

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product detail with comments - 🚨 XSS vulnerable"""
    product = next((p for p in products if p['id'] == product_id), None)
    
    if not product:
        return "Product not found", 404
    
    product_comments = comments.get(product_id, [])
    
    # Check for XSS
    xss_found = False
    for comment in product_comments:
        if '<' in comment['text'] and '>' in comment['text']:
            xss_found = True
    
    return render_template('product.html', 
        product=product, 
        comments=product_comments,
        xss_alert=xss_found
    )


@app.route('/add_comment/<int:product_id>', methods=['POST'])
def add_comment(product_id):
    """🚨 XSS - Comments not escaped before display"""
    comment_text = request.form.get('comment', '')
    
    if not comment_text:
        return redirect(f'/product/{product_id}')
    
    if product_id not in comments:
        comments[product_id] = []
    
    comments[product_id].append({
        "text": comment_text,  # ❌ NOT ESCAPED - XSS VULNERABLE
        "author": session.get('user', 'Anonymous')
    })
    
    return redirect(f'/product/{product_id}')

# ============================================
# SHOPPING CART
# ============================================

@app.route('/cart')
def cart():
    """🚨 INSECURE DESERIALIZATION - Using pickle on untrusted data"""
    user_id = session.get('user_id', 'guest')
    user_cart = cart_items.get(user_id, [])
    
    alert_msg = None
    if user_cart:
        try:
            cart_pickle = base64.b64encode(pickle.dumps(user_cart)).decode()
            alert_msg = {
                "type": "danger",
                "title": "🚨 INSECURE DESERIALIZATION!",
                "message": "Good catch! This cart uses pickle.loads() on untrusted data!",
                "explanation": "pickle.loads() can execute arbitrary Python code during deserialization",
                "impact": "Attacker could achieve Remote Code Execution (RCE) - full server compromise!"
            }
        except:
            pass
    
    return render_template('cart.html', cart_items=user_cart, alert=alert_msg)


@app.route('/add_to_cart/<int:product_id>')
def add_to_cart(product_id):
    """Add item to cart using insecure pickle"""
    product = next((p for p in products if p['id'] == product_id), None)
    
    if not product:
        return "Product not found", 404
    
    user_id = session.get('user_id', 'guest')
    if user_id not in cart_items:
        cart_items[user_id] = []
    
    cart_items[user_id].append(product)
    
    return redirect('/')


@app.route('/remove_from_cart/<int:index>')
def remove_from_cart(index):
    """Remove item from cart"""
    user_id = session.get('user_id', 'guest')
    if user_id in cart_items and 0 <= int(index) < len(cart_items[user_id]):
        cart_items[user_id].pop(int(index))
    return redirect('/cart')

# ============================================
# AUTHENTICATION
# ============================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login - 🚨 passwords stored plaintext"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        # ❌ PLAINTEXT PASSWORD COMPARISON
        user = next((u for u in users if u['email'] == email and u['password'] == password), None)
        
        if user:
            session['user'] = user['email']
            session['user_id'] = user['id']
            session['is_admin'] = user['is_admin']
            return redirect('/')
        else:
            return render_template('login.html', error="Invalid email or password")
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register - 🚨 stores plaintext password"""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if any(u['email'] == email for u in users):
            return render_template('register.html', error="Email already registered")
        
        users.append({
            "id": len(users) + 1,
            "email": email,
            "password": password,  # ❌ PLAINTEXT STORAGE!
            "is_admin": False
        })
        
        session['user'] = email
        session['user_id'] = len(users)
        session['is_admin'] = False
        return redirect('/')
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    """Logout"""
    session.clear()
    return redirect('/')

# ============================================
# ADMIN PANEL - NO AUTHENTICATION!
# ============================================

@app.route('/admin')
def admin_panel():
    """🚨 MISSING AUTHENTICATION - No login check"""
    
    alert_msg = None
    if 'user' not in session:
        alert_msg = {
            "type": "danger",
            "title": "🚨 MISSING AUTHENTICATION!",
            "message": "Good catch! You accessed admin panel WITHOUT LOGGING IN!",
            "explanation": "No authentication check on admin endpoint",
            "impact": "Attacker can see all users, passwords, delete users, modify data, full system compromise!",
            "lesson": "Check: if 'user' not in session: return 403"
        }
    
    return render_template('admin.html', users=users, alert=alert_msg)


@app.route('/admin/show_passwords')
def admin_show_passwords():
    """Show plaintext passwords - 🚨 PLAINTEXT PASSWORD STORAGE"""
    return render_template('admin_passwords.html', users=users)


@app.route('/admin/show_secrets')
def admin_show_secrets():
    """Show hardcoded secrets - 🚨 HARDCODED SECRETS"""
    return render_template('admin_secrets.html')


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    """🚨 Delete user without authentication"""
    global users
    users = [u for u in users if u['id'] != user_id]
    return jsonify({"status": "User deleted"})

# ============================================
# CHECKOUT - LOGIC FLAW
# ============================================

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """Checkout - 🚨 accepts any price from client"""
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        quantity = int(request.form.get('quantity', 1))
        price = float(request.form.get('price', 0))  # ❌ ACCEPTS CLIENT PRICE
        
        if price < 0:
            return render_template('checkout.html',
                alert={
                    "type": "danger",
                    "title": "🚨 BUSINESS LOGIC FLAW!",
                    "message": f"Good catch! You submitted NEGATIVE price: ${price}",
                    "explanation": "Application accepted price directly from client input without validation!",
                    "impact": "Customer receives MONEY instead of paying! Business loses thousands per transaction!",
                    "lesson": "Always fetch prices from database, never trust client input"
                }
            )
        
        total = price * quantity
        return render_template('checkout.html',
            total=total,
            alert={
                "type": "success",
                "title": "Payment Processed",
                "message": f"Total: ${total}"
            }
        )
    
    return render_template('checkout.html')


# ============================================
# LEGACY ROUTES (for backwards compatibility)
# ============================================

@app.route('/config')
def show_config():
    """Show hardcoded secrets"""
    return render_template('admin_secrets.html')


@app.route('/show_password')
def show_password():
    """Show plaintext passwords"""
    return render_template('admin_passwords.html', users=users)


@app.route('/admin/users')
def admin_users():
    """Admin panel"""
    alert_msg = {
        "type": "danger",
        "title": "🚨 MISSING AUTHENTICATION!",
        "message": "Good catch! You accessed admin panel WITHOUT LOGGING IN!",
        "explanation": "No authentication check on admin endpoint",
        "impact": "Attacker can see all users and passwords!",
    }
    return render_template('admin.html', users=users, alert=alert_msg)


if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚨 VULNERABLE E-COMMERCE APP")
    print("="*70)
    print("\n📖 VULNERABILITIES INCLUDED:")
    print("  1. SQL Injection          → /search")
    print("  2. XSS                    → /product/1 (add comment)")
    print("  3. Insecure Deserialization → /cart (pickle RCE)")
    print("  4. Hardcoded Secrets      → /admin/show_secrets")
    print("  5. Missing Authentication → /admin (no login!)")
    print("  6. Plaintext Passwords    → /admin/show_passwords")
    print("  7. Business Logic Flaw    → /checkout (negative price)")
    print("  8. Missing Security Headers → All pages (F12 DevTools)")
    print("\n🌐 Open: http://localhost:5000")
    print("💡 Demo Credentials:")
    print("   Email: admin@example.com")
    print("   Password: admin123")
    print("="*70 + "\n")
    
    # ✅ FIXED: host='0.0.0.0' allows Docker to access the app
    app.run(debug=True, port=5000, host='0.0.0.0')