from flask import Flask, render_template, request, jsonify, redirect, session
import os
import sys
path = os.path.abspath(r"main.py")
path = path.rstrip(r"\main.py")
sys.path.append(path)
from main import *
from threat_leaderboard import generate_leaderboard


#variables
upload = r'\uploads'
submitToDatabase=False

app = Flask(__name__)
app.secret_key = "asdfghjkdasdfghjklzxcvbhjkioerfghnujhbfvbvbnmfgbxcvgyuikerthv"
app.config['uploadFolder'] = upload

@app.before_request
def set_session():
    session['submittodatabase'] = False

@app.route('/', methods=['GET', 'POST'])
def index():
    session['submittodatabase'] = False
    return render_template('index.html')

@app.route('/about', methods=['GET', 'POST'])
def about():
    with open(r'WEB_GUI\about.txt', 'r') as f:
        s=f.readlines()
        output=s
    return render_template('about.html', output=output)

@app.route('/credits', methods=['GET', 'POST'])
def credits():
    return render_template('credits.html')

@app.route('/license', methods=['GET', 'POST'])
def license():
    with open(r'LICENSE', 'r') as l:
        lines = l.readlines()
        output = lines
    return render_template('license.html', output=output)

@app.route('/leaderboard')
def leaderboard():
    output = generate_leaderboard()
    return render_template('leaderboard.html', output=output)

@app.route('/scan_link', methods=['GET', 'POST'])
def sclink():
    link = request.form.get('scan_link')
    report = scan_link(link)
    output=report
    output = output.splitlines()
    session['report'] = output
    return render_template('report.html', output=output)

@app.route('/scan_singular_message', methods=['GET', 'POST'])
def scMsg():
    msg = request.form.get('scan_message')
    report = single_scan(msg)
    output=report
    output = output.splitlines()
    session['report'] = output
    return render_template('report.html', output=output)

@app.route('/scan_whatsapp', methods=['GET', 'POST'])
def scWhatsapp():
    author = request.form.get('author')
    output=''
    if 'whatsapp_report' in request.files:
        whatsapp_file = request.files['whatsapp_report']
        filename = whatsapp_file.filename
        path = os.path.join(app.config['uploadFolder'], filename)
        whatsapp_file.save(path)
        report = whatsapp_scan(path, author)
        output = report
        output = output.splitlines()
        session['report'] = output
        os.remove(path)
    else:
        output = "No WhatsApp file uploaded."
    return render_template('report.html', output=output)

@app.route('/scan_email', methods=['GET', 'POST'])
def scEmail():
    output=''
    if 'email_report' in request.files:
        eml_file = request.files['email_report']
        filename = eml_file.filename
        path = os.path.join(app.config['uploadFolder'], filename)
        eml_file.save(path)
        report = eml_scan(path)
        output = report
        output = output.splitlines()
        session['report'] = output
        os.remove(path)
    else:
        output = "No .eml file uploaded."
    return render_template('report.html', output=output)

@app.route('/scan_file', methods=['GET', 'POST'])
def scFile():
    output=''
    if 'scan_file' in request.files:
        file = request.files['scan_file']
        filename = file.filename
        path = os.path.join(app.config['uploadFolder'], filename)
        file.save(path)
        output = file_scan(path)
        output = output.splitlines()
        session['report'] = output
        os.remove(path)
    else:
        output = "No file uploaded."
    return render_template('report.html', output=output)

@app.route('/submitToDatabase', methods=['GET', 'POST'])
def submitYes():
    session['submittodatabase'] = True
    update_to_db(True, session['report'])
    return redirect('/')

@app.route('/dontSubmitToDatabase', methods=['GET', 'POST'])
def submitNo():
    session['submittodatabase'] = False
    return redirect('/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
