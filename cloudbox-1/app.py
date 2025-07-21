from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer
import boto3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = 'secret123'

# AWS Setup
dynamodb = boto3.resource('dynamodb', region_name='eu-north-1')
table = dynamodb.Table('cloudbox_users')
s3 = boto3.client('s3', region_name='eu-north-1')
bucket_name = 'cloudbox-files-ram123'

# Email Settings (🔁 Replace These)
EMAIL_ADDRESS = 'priyahari58095@gmail.com'
EMAIL_PASSWORD = 'yerd tcwz gyhe qfbo'

# Token Serializer
s = URLSafeTimedSerializer(app.secret_key)

# Email sending function
def send_verification_email(email):
    token = s.dumps(email, salt='email-confirm')
    link = url_for('verify_email', token=token, _external=True)

    subject = 'CloudBox Email Verification'
    body = f'Click the link to verify your email:\n{link}\n\nThis link will expire in 1 hour.'

    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"[EMAIL] Verification sent to: {email}")
    except Exception as e:
        print(f"[EMAIL ERROR]: {e}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        response = table.get_item(Key={'email': email})
        if 'Item' in response:
            flash("Email already registered. Try login.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        table.put_item(Item={
            'email': email,
            'name': name,
            'password': hashed_password,
            'is_verified': False
        })

        send_verification_email(email)
        flash("Successfully registered. Please verify your email.")
        return redirect(url_for('login', email=email, password=password))

    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        return "Invalid or expired token. Please try again."

    table.update_item(
        Key={'email': email},
        UpdateExpression='SET is_verified = :val',
        ExpressionAttributeValues={':val': True}
    )

    return render_template('email_verified.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    email_prefill = request.args.get('email', '')
    password_prefill = request.args.get('password', '')

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        response = table.get_item(Key={'email': email})
        user = response.get('Item')

        if not user:
            flash("Email not registered! Try registering.")
            return redirect(url_for('register'))

        if not user.get('is_verified'):
            return render_template('email_verification_needed.html', email=email)

        if check_password_hash(user['password'], password):
            session['user'] = email
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Incorrect password.")
            return redirect(url_for('login'))

    return render_template('login.html', email_prefill=email_prefill, password_prefill=password_prefill)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    response = table.get_item(Key={'email': session['user']})
    name = response.get('Item', {}).get('name', 'User')

    user_prefix = f"{session['user']}/"
    try:
        s3_response = s3.list_objects_v2(Bucket=bucket_name, Prefix=user_prefix)
        contents = s3_response.get('Contents', [])
        files = [obj['Key'].split('/', 1)[-1] for obj in contents if obj['Key'] != user_prefix]
    except Exception as e:
        flash(f"Error retrieving files: {str(e)}")
        files = []

    return render_template('dashboard.html', name=name, files=files)

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out.")
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files['file']
        if not file or file.filename == '':
            flash("No file selected.")
            return redirect(url_for('upload'))

        filename = secure_filename(file.filename)
        s3_key = f"{session['user']}/{filename}"

        try:
            s3.upload_fileobj(file, bucket_name, s3_key)
            flash("Upload successful.")
        except Exception as e:
            flash(f"Failed to upload: {str(e)}")
        return redirect(url_for('upload'))

    return render_template('upload.html')

@app.route('/files')
def files():
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    user_prefix = f"{session['user']}/"
    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=user_prefix)
        contents = response.get('Contents', [])
        files = [obj['Key'].split('/', 1)[-1] for obj in contents if obj['Key'] != user_prefix]
    except Exception as e:
        flash(f"Error getting files: {str(e)}")
        files = []

    return render_template('files.html', files=files)

@app.route('/download/<filename>')
def download_file(filename):
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    s3_key = f"{session['user']}/{filename}"
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': s3_key},
            ExpiresIn=60
        )
        return redirect(url)
    except Exception as e:
        flash(f"Download failed: {str(e)}")
        return redirect(url_for('files'))

@app.route('/delete/<filename>')
def delete_file(filename):
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    s3_key = f"{session['user']}/{filename}"
    try:
        s3.delete_object(Bucket=bucket_name, Key=s3_key)
        flash("File deleted.")
    except Exception as e:
        flash(f"Delete failed: {str(e)}")

    return redirect(url_for('dashboard'))

@app.route('/preview/<filename>')
def preview_file(filename):
    if 'user' not in session:
        flash("Please log in first.")
        return redirect(url_for('login'))

    s3_key = f"{session['user']}/{filename}"
    try:
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': s3_key},
            ExpiresIn=60
        )
        return redirect(url)
    except Exception as e:
        flash(f"Preview failed: {str(e)}")
        return redirect(url_for('files'))

if __name__ == '__main__':
    app.run(debug=True)
