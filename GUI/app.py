from flask import Flask, render_template, request, jsonify, redirect, session
import os
import sys
sys.path.append( r'C:\Users\USER\Desktop\Unselphish')
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
    return render_template('about.html')

@app.route('/credits', methods=['GET', 'POST'])
def credits():
    return render_template('credits.html')

@app.route('/license', methods=['GET', 'POST'])
def license():
    return render_template('license.html')

@app.route('/leaderboard')
def leaderboard():
    output = generate_leaderboard()
    return render_template('leaderboard.html', output=output)

@app.route('/scan_link', methods=['GET', 'POST'])
def sclink():
    link = request.form.get('scan_link')
    report = scan_link(link)
    output=report
    session['report'] = output
    return render_template('report.html', output=output)

@app.route('/scan_singular_message', methods=['GET', 'POST'])
def scMsg():
    msg = request.form.get('scan_message')
    report = single_scan(msg)
    output=report
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

'''
@app.route('/update_toggle_status', methods=['POST'])
def update_toggle_status():
    # Get the boolean value from the request data
    data = request.json
    is_enabled = data.get('is_enabled', False)

    # Your Python logic with the boolean value here...
    # For now, let's just return a simple response
    if is_enabled:
        response = {'message': True}
    else:
        response = {'message': False}

    return(jsonify(response))
'''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
