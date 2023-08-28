from flask import Flask, render_template, request, jsonify, redirect, session
import os
import threading
from scanner_app import *
from features.threat_leaderboard import generate_leaderboard


#variables
global report_thread
upload = r'uploads'
report = None
category = None
report_thread = None


app = Flask(__name__)
app.secret_key = "asdfghjkdasdfghjklzxcvbhjkioerfghnujhbfvbvbnmfgbxcvgyuikerthv"
app.config['uploadFolder'] = upload

@app.before_request
def set_session():
    pass

@app.route('/', methods=['GET', 'POST'])
def index():
    session.clear()
    return render_template('index.html')

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

@app.route('/credits', methods=['GET', 'POST'])
def credits():
    return render_template('credits.html')

@app.route('/license', methods=['GET', 'POST'])
def license():
    with open(r'LICENSE', 'r') as l:
        lines = l.readlines()
        output = lines
    return render_template('license.html', output=output)


@app.route('/leaderboard', methods=['GET', 'POST'])
def leaderboard():
    threat_list = generate_leaderboard()
    output_list = []

    # Cleaning the data
    for threat in threat_list:
        local_category = threat['Category']
        local_report = threat['Report']
        local_report = local_report.splitlines()
        output = [f'Category: {local_category}']
        output.extend(local_report)
        output_list.append(output)

    print(output_list)
        
    return render_template('leaderboard.html', output_list=output_list)


@app.route('/scan-report', methods=['GET', 'POST'])
def report_display():
    global report_thread

    if report_thread.is_alive():
        return render_template('load.html', redirect_url = '/scan-report')
    elif not report_thread.is_alive():
        output = report
        session['report'] = output
        output = output.splitlines()
        session['category'] = category
        return render_template('report.html', output=output)
    else:
        print("Error")


def generate_report(sc_type: int, input_var, auth = None):
    global report
    global category
    if sc_type == 1:
        global report
        url2scan = input_var
        report = scan_link(url2scan)
        category = 'MALICIOUS LINK'

    if sc_type == 2:

        emlfile = input_var
        report = eml_scan(emlfile)
        category = 'MALICIOUS EMAIL'
        
    if sc_type == 3:
        msg2scan = input_var
        report = single_scan(msg2scan)
        category = 'MALICIOUS MESSAGE'

    if sc_type == 4:
        chattxt = input_var
        report = whatsapp_scan(chattxt, auth)
        category = 'MALICIOUS WHATSAPP'

    if sc_type == 5:
        fpath = input_var
        report = file_scan(fpath)
        category = 'MALICIOUS FILE'
    

@app.route('/scan_link', methods=['GET', 'POST'])
def sclink():
    global report_thread
    link = request.form.get('scan_link')
    report_thread = threading.Thread(target=generate_report, args=(1, link))
    report_thread.start()
    return render_template('load.html', redirect_url = '/scan-report')


@app.route('/scan_email', methods=['GET', 'POST'])
def scEmail():
    global report_thread
    if 'email_report' in request.files:
        eml_file = request.files['email_report']
        filename = eml_file.filename
        path = os.path.join(app.config['uploadFolder'], filename)
        eml_file.save(path)
        report_thread = threading.Thread(target=generate_report, args=(2, path))
        report_thread.start()
    else:
        output = "No .eml file uploaded."

    return redirect('/scan-report')
    

@app.route('/scan_singular_message', methods=['GET', 'POST'])
def scMsg():
    global report_thread
    msg = request.form.get('scan_message')
    report_thread = threading.Thread(target=generate_report, args=(3, msg))
    report_thread.start()

    return redirect('/scan-report')

@app.route('/scan_whatsapp', methods=['GET', 'POST'])
def scWhatsapp():
    global report_thread
    author = request.form.get('author')
    if 'whatsapp_report' in request.files:
        whatsapp_file = request.files['whatsapp_report']
        filename = whatsapp_file.filename
        path = os.path.join(app.config['uploadFolder'], filename)
        whatsapp_file.save(path)
        report_thread = threading.Thread(target=generate_report, args=(4, path, author))
        report_thread.start()
   
    else:
        output = "No WhatsApp file uploaded."

    return redirect('/scan-report')

@app.route('/scan_file', methods=['GET', 'POST'])
def scFile():
    global report_thread
    if 'scan_file' in request.files:
        file = request.files['scan_file']
        filename = file.filename
        path = os.path.join(app.config['uploadFolder'], filename)
        file.save(path)
        report_thread = threading.Thread(target=generate_report, args=(5, path))
        report_thread.start()
        
    else:
        output = "No file uploaded."

    return redirect('/scan-report')

@app.route('/submitToDatabase', methods=['GET', 'POST'])
def submitYes():
    session['submittodatabase'] = True
    update_to_db(True, session['report'], session['category'])
    return redirect('/')

@app.route('/dontSubmitToDatabase', methods=['GET', 'POST'])
def submitNo():
    session['submittodatabase'] = False
    return redirect('/')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
