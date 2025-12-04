from flask import Flask, jsonify, request
import time
import threading

app = Flask(__name__)

# --- Vulnerable State ---
# Simulate a limited resource (e.g., a coupon that can be used once, or 1 item in stock)
db = {
    "stock": 1,
    "balance": 100
}
# A lock that we INTENTIONALLY do not use correctly in the vulnerable endpoint
_lock = threading.Lock()

@app.route('/reset', methods=['POST'])
def reset():
    """Reset the lab state."""
    db["stock"] = 1
    db["balance"] = 100
    return jsonify({"message": "State reset", "db": db})

@app.route('/buy', methods=['POST'])
def buy():
    """
    VULNERABLE ENDPOINT
    Logic: Check stock -> Sleep (simulate DB latency) -> Decrement stock
    """
    user_id = request.headers.get("X-User-ID", "anon")
    
    # 1. CHECK: Do we have stock?
    if db["stock"] > 0:
        
        # --- The Race Window ---
        # We simulate a tiny delay (e.g., database read/write lag or external API call)
        # This 50ms window is where Scalpel Racer needs to fit parallel requests.
        time.sleep(0.05) 
        
        # 2. ACT: Decrement stock
        db["stock"] -= 1
        
        return jsonify({
            "status": "success", 
            "msg": "Item purchased!", 
            "new_stock": db["stock"]
        }), 200
    else:
        return jsonify({
            "status": "failure", 
            "msg": "Out of stock!", 
            "new_stock": db["stock"]
        }), 400

@app.route('/info', methods=['GET'])
def info():
    return jsonify(db)

if __name__ == '__main__':
    # Run threaded to allow concurrent request processing
    print("[*] Vulnerable Lab running on http://127.0.0.1:5000")
    app.run(debug=False, port=5000, threaded=True)