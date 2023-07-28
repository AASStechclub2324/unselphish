import flask

app=flask.Flask(__name__)

@app.route('/')
def home():
    return flask.render_template('home.html')

@app.route('/about')
def about():
    return flask.render_template('about.html')

@app.route('/credits')
def credits():
    return flask.render_template('credits.html')

@app.route('/license')
def license():
    return flask.render_template('license.html')

@app.route('/install_cli')
def install_cli():
    return flask.render_template('install_cli.html')

@app.route('/scan_link', methods=['POST'])
def scan_link():
    link = flask.request.form.get('scan_link')
    
    output = 'this is output, scan link'
    
    return flask.render_template('home.html', output=output)

@app.route('/scan_domain', methods=['POST'])
def scan_domain():
    domain = flask.request.form.get('scan_domain')
    
    output = 'this is output, scan domain'
    
    return flask.render_template('home.html', output=output)

@app.route('/scan_singular_message', methods=['POST'])
def scMsg():
    msg = flask.request.form.get('scan_message')
    
    output = 'this is output, message'
    
    return flask.render_template('home.html', output=output)

@app.route('/whatsapp_report', methods=['POST'])
def whatsapp_report():
    output=''
    if 'whatsapp_report' in flask.request.files:
        whatsapp_file = flask.request.files['whatsapp_report']
        output = 'this is output, wp'
    else:
        output = "No WhatsApp file uploaded."
    return flask.render_template('home.html', output=output)

@app.route('/email_report', methods=['POST'])
def email_report():
    output=''
    if 'email_report' in flask.request.files:
        eml_file = flask.request.files['email_report']
        output = 'this is output, eml'
    else:
        output = "No .eml file uploaded."
    return flask.render_template('home.html', output=output)

@app.route('/scan_file', methods=['POST'])
def scan_file():
    output=''
    if 'scan_file' in flask.request.files:
        file = flask.request.files['scan_file']
        output = 'this is output, fl'
    else:
        output = "No file uploaded."
    return flask.render_template('home.html', output=output)

if __name__ == '__main__':
   app.run()