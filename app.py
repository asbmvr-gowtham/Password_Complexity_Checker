from flask import Flask, render_template, request, jsonify
import math
import re

try:
    from zxcvbn import zxcvbn
    has_zxcvbn = True
except ImportError:
    has_zxcvbn = False

app = Flask(__name__)

# ✅ Load the rockyou.txt file once during app startup
rockyou_passwords = set()
try:
    with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as file:
        rockyou_passwords = set(line.strip() for line in file)
except FileNotFoundError:
    print("rockyou.txt file not found!")

def check_password_in_rockyou(password):
    return password in rockyou_passwords

def calculate_entropy(password):
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'[0-9]', password): charset += 10
    if re.search(r'[^a-zA-Z0-9]', password): charset += 32

    length = len(password)
    entropy = math.log2(charset) * length if charset else 0
    max_entropy = math.log2(94) * length if length else 0
    normalized_score = (entropy / max_entropy) * 100 if max_entropy else 0
    return round(entropy, 2), round(normalized_score, 2)

def has_repeated_patterns(password):
    return bool(re.search(r'(.)\1{2,}', password))

def has_sequential_chars(password):
    sequences = ['abcdefghijklmnopqrstuvwxyz', '0123456789', 'qwertyuiop', 'asdfghjkl', 
                 'zxcvbnm', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '!@#$%^&*()_+']
    lower_pw = password.lower()
    for seq in sequences:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in lower_pw:
                return True
    return False

def is_too_short(password, min_length=8):
    return len(password) < min_length

def matches_consecutive_pattern(password):
    return bool(re.match(r'^[A-Z][a-z]{4,6}.*(?=.*\d)(?=.*\W)', password))

def get_zxcvbn_score(password):
    if has_zxcvbn:
        return zxcvbn(password)['score']
    return -1

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check-password', methods=['POST'])
def check_password():
    password = request.json.get('password', '')
    result = {
        'password': password,
        'breached': check_password_in_rockyou(password),
        'repeated': has_repeated_patterns(password),
        'sequential': has_sequential_chars(password),
        'too_short': is_too_short(password),
        'common_structure': matches_consecutive_pattern(password),
    }

    entropy, entropy_score = calculate_entropy(password)
    result['entropy'] = entropy
    result['entropy_score'] = entropy_score

    z_score = get_zxcvbn_score(password)
    result['zxcvbn_score'] = z_score

    deductions = 0
    if result['repeated']: deductions += 20
    if result['sequential']: deductions += 20
    if result['too_short']: deductions += 10
    if result['common_structure']: deductions += 50

    count = 100 - deductions
    if result['breached']:
        result['ppc_score'] = 0
        result['status'] = "Breached — Go it right now!"
    else:
        z_score_percent = (z_score / 4) * 100 if z_score >= 0 else 0
        final_score = (entropy_score + z_score_percent + count) / 3
        result['ppc_score'] = round(final_score, 2)
        result['status'] = "Safe" if final_score >= 70 else "Weak"

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
