from flask import Flask, render_template, request, jsonify

#variables
submitToDatabase=True

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/credits')
def credits():
    return render_template('credits.html')

@app.route('/license')
def license():
    return render_template('license.html')

@app.route('/scan_link', methods=['POST'])
def scan_link():
    link = request.form.get('scan_link')
    output=link
    return render_template('report.html', output=output)

@app.route('/scan_domain', methods=['POST'])
def scan_domain():
    domain = request.form.get('scan_domain')
    output=domain    
    return render_template('report.html', output=output)

@app.route('/scan_message', methods=['POST'])
def scMsg():
    msg = request.form.get('scan_message')
    output=msg    
    return render_template('report.html', output=output)

@app.route('/whatsapp_report', methods=['POST'])
def whatsapp_report():
    output=''
    if 'whatsapp_report' in request.files:
        whatsapp_file = request.files['whatsapp_report']
        output = whatsapp_file.filename
    else:
        output = "No WhatsApp file uploaded."
    return render_template('report.html', output=output)

@app.route('/email_report', methods=['POST'])
def email_report():
    output=''
    if 'email_report' in request.files:
        eml_file = request.files['email_report']
        output = eml_file.filename
    else:
        output = "No .eml file uploaded."
    return render_template('report.html', output=output)

@app.route('/scan_file', methods=['POST'])
def scan_file():
    output=''
    if 'scan_file' in request.files:
        file = request.files['scan_file']
        output = file.filename
    else:
        output = "No file uploaded."
    return render_template('report.html', output=output)

@app.route('/submitToDatabase', methods=['POST'])
def submitYes():
    global submitToDatabase
    submitToDatabase = True
    print(submitToDatabase)
    return render_template('index.html')

@app.route('/dontSubmitToDatabase', methods=['POST'])
def submitNo():
    global submitToDatabase
    submitToDatabase = False
    print(submitToDatabase)
    return render_template('index.html')

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
    app.run(host='0.0.0.0')
