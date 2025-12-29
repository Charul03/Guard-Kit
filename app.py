import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.utils import secure_filename
from guardkit.db import db, User, Report
from guardkit import network, websec, malware, crypto_utils, forensics
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import datetime

# Config
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'zip', 'exe', 'bin', 'doc', 'docx'}

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config.from_object('config')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max

# Ensure folders
os.makedirs('instance', exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize DB
db.init_app(app)
with app.app_context():
    db.create_all()

# Login manager
login_manager = LoginManager()
login_manager.login_view = 'signin'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return render_template('index.html')

# ------- Auth -------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        email = request.form.get('email', '').strip() or None

        if not username or not password:
            flash('Provide username and password', 'danger')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('signup'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Account created. Please sign in.', 'success')
        return redirect(url_for('signin'))
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Signed in successfully.', 'success')
            return redirect(url_for('index'))
        flash('Invalid credentials', 'danger')
    return render_template('signin.html')

@app.route('/signout')
@login_required
def signout():
    logout_user()
    flash('Signed out', 'info')
    return redirect(url_for('index'))

# ------- Network Scanner -------
@app.route('/network', methods=['GET', 'POST'])
@login_required
def network_view():
    result = None
    target = None
    if request.method == 'POST':
        target = request.form.get('host', '').strip()
        ports_str = request.form.get('ports', '').strip()
        timeout = float(request.form.get('timeout', '0.8'))
        max_threads = int(request.form.get('max_threads', '200'))
        try:
            ports = network.parse_ports(ports_str)
        except Exception:
            flash('Invalid port format (use formats like: 80,443,1-1024)', 'danger')
            return redirect(url_for('network_view'))

        try:
            result = network.port_scan(target, ports=ports, timeout=timeout, max_threads=max_threads)
            # Save report
            rep = Report(user_id=current_user.id, title=f'Network scan: {target}', content=str(result))
            db.session.add(rep); db.session.commit()
        except Exception as e:
            flash(f'Error scanning: {e}', 'danger')
    return render_template('network.html', result=result, target=target)

# ------- Web security (header analyzer) -------
@app.route('/websec', methods=['GET', 'POST'])
@login_required
def websec_view():
    analysis = None
    url = None
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        analysis = websec.check_security_headers(url)
        rep = Report(user_id=current_user.id, title=f'Header analysis: {url}', content=str(analysis))
        db.session.add(rep); db.session.commit()
    return render_template('websec.html', analysis=analysis, url=url)

# ------- Malware (file hash) -------
@app.route('/malware', methods=['GET', 'POST'])
@login_required
def malware_view():
    hashes = None
    vt_info = None
    filename = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            hashes = malware.compute_hashes(path)
            vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
            if vt_key:
                try:
                    vt_info = malware.optional_virustotal_check(vt_key, hashes['sha256'])
                except Exception as e:
                    vt_info = {'error': str(e)}
            rep = Report(user_id=current_user.id, title=f'File scan: {filename}', content=str(hashes))
            db.session.add(rep); db.session.commit()
        else:
            flash('No file uploaded or file type not allowed', 'danger')
    return render_template('malware.html', hashes=hashes, vt_info=vt_info, filename=filename)

# ------- Crypto (Fernet) -------
@app.route('/crypto', methods=['GET', 'POST'])
@login_required
def crypto_view():
    gen_key = None
    enc_out = None
    dec_out = None
    if request.method == 'POST':
        if 'generate_key' in request.form:
            gen_key = crypto_utils.generate_key()
        elif 'encrypt' in request.form:
            file = request.files.get('file')
            key = request.form.get('key', '').strip()
            if file and key:
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                enc_out = crypto_utils.encrypt_file(path, key)
                flash(f'Encrypted to {enc_out}', 'success')
            else:
                flash('File and key required for encryption', 'danger')
        elif 'decrypt' in request.form:
            file = request.files.get('file')
            key = request.form.get('key', '').strip()
            if file and key:
                filename = secure_filename(file.filename)
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                try:
                    dec_out = crypto_utils.decrypt_file(path, key)
                    flash(f'Decrypted to {dec_out}', 'success')
                except Exception as e:
                    flash(f'Decrypt failed: {e}', 'danger')
            else:
                flash('File and key required for decryption', 'danger')
    return render_template('crypto.html', gen_key=gen_key, enc_out=enc_out, dec_out=dec_out)

# ------- Forensics (metadata + hex) -------
@app.route('/forensics', methods=['GET', 'POST'])
@login_required
def forensics_view():
    meta = None
    hex_preview_text = None
    filename = None
    if request.method == 'POST':
        file = request.files.get('file')
        if file:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(path)
            meta = forensics.file_metadata(path)
            hex_preview_text = forensics.hex_preview(path, length=512)
            rep = Report(user_id=current_user.id, title=f'Forensic: {filename}', content=str(meta))
            db.session.add(rep); db.session.commit()
        else:
            flash('Upload a file', 'danger')
    return render_template('forensics.html', meta=meta, hex_preview=hex_preview_text, filename=filename)

# ------- Reports -------
@app.route('/reports')
@login_required
def reports():
    my_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.timestamp.desc()).all()
    return render_template('report.html', reports=my_reports)

# ------- Serve uploads (download) -------
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
