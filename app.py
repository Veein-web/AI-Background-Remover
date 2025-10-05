# =================================================================
# 1. استيراد المكتبات
# =================================================================
import os
import io
from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from rembg import remove
from PIL import Image
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from sqlalchemy.orm.exc import NoResultFound
from dotenv import load_dotenv # <-- [جديد] لاستيراد المكتبة

# =================================================================
# 2. تحميل متغيرات البيئة من ملف .env
# =================================================================
load_dotenv()
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

# =================================================================
# 3. إعداد التطبيق والمفاتيح
# =================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-that-you-should-change'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- [تحديث أمني مهم] ---
# قراءة المفاتيح من متغيرات البيئة بدلاً من كتابتها مباشرة
app.config['GOOGLE_OAUTH_CLIENT_ID'] = os.environ.get('GOOGLE_OAUTH_CLIENT_ID')
app.config['GOOGLE_OAUTH_CLIENT_SECRET'] = os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET')

# =================================================================
# 4. إعداد قاعدة البيانات و Flask-Dance
# =================================================================
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

google_bp = make_google_blueprint(
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"],
    redirect_url='/login/google/authorized'
 )
app.register_blueprint(google_bp, url_prefix="/login")

# ... (باقي الكود يبقى كما هو تمامًا) ...
# =================================================================
# 5. نماذج قاعدة البيانات والدوال المساعدة
# =================================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100), nullable=True)
    name = db.Column(db.String(1000))
    credits = db.Column(db.Integer, default=1)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@oauth_authorized.connect_via(google_bp)
def google_logged_in(blueprint, token):
    if not token:
        flash("Failed to log in with Google.", "danger")
        return redirect(url_for("login"))

    resp = blueprint.session.get("/oauth2/v2/userinfo")
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "danger")
        return redirect(url_for("login"))
    
    user_info = resp.json()
    user_email = user_info["email"]

    try:
        user = User.query.filter_by(email=user_email).one()
    except NoResultFound:
        user = User(
            email=user_email,
            name=user_info.get("name", user_email),
            password=None
        )
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully via Google!", "success")

    login_user(user)
    return redirect(url_for("remove_bg"))

# =================================================================
# 6. المسارات (Routes)
# =================================================================
UPLOAD_FOLDER = 'static/uploads'
PROCESSED_FOLDER = 'static/processed'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROCESSED_FOLDER'] = PROCESSED_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)
DOWNLOAD_QUALITIES = { "sd": {"name": "SD (Preview)", "size": 600, "cost": 0}, "hd": {"name": "HD (1280px)", "size": 1280, "cost": 1}, "fhd": {"name": "Full HD (1920px)", "size": 1920, "cost": 2}, "2k": {"name": "2K (2560px)", "size": 2560, "cost": 3} }

@app.route('/')
def index(): return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('remove_bg'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if not user or not user.password or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.', 'danger')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('remove_bg'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect(url_for('remove_bg'))
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists.', 'danger')
            return redirect(url_for('signup'))
        new_user = User(email=email, name=name, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You get 1 free HD credit. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/remove', methods=['GET', 'POST'])
@login_required
def remove_bg():
    if request.method == 'POST':
        if 'file' not in request.files: flash('No file part', 'danger'); return redirect(request.url)
        file = request.files['file']
        if file.filename == '': flash('No selected file', 'danger'); return redirect(request.url)
        if file:
            original_filename = secure_filename(file.filename)
            original_path = os.path.join(app.config['UPLOAD_FOLDER'], original_filename)
            file.save(original_path)
            processed_filename = f"{os.path.splitext(original_filename)[0]}_processed.png"
            processed_path = os.path.join(app.config['PROCESSED_FOLDER'], processed_filename)
            try:
                input_image = Image.open(original_path)
                output_image = remove(input_image)
                output_image.save(processed_path)
                return render_template('remove_bg.html', original_image=original_filename, processed_image=processed_filename, qualities=DOWNLOAD_QUALITIES)
            except Exception as e:
                flash(f'An error occurred during processing: {e}', 'danger')
                return redirect(url_for('remove_bg'))
    return render_template('remove_bg.html')

@app.route('/download/<filename>/<quality>')
@login_required
def download_image(filename, quality):
    if quality not in DOWNLOAD_QUALITIES: flash('Invalid quality selected.', 'danger'); return redirect(url_for('remove_bg'))
    selected_quality = DOWNLOAD_QUALITIES[quality]
    cost = selected_quality['cost']
    if current_user.credits < cost: flash(f'You need {cost} credits for this download, but you only have {current_user.credits}.', 'danger'); return redirect(url_for('pricing'))
    try:
        processed_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
        img = Image.open(processed_path)
        target_width = selected_quality['size']; w_percent = (target_width / float(img.size[0])); h_size = int((float(img.size[1]) * float(w_percent)))
        resized_img = img.resize((target_width, h_size), Image.Resampling.LANCZOS)
        current_user.credits -= cost
        db.session.commit()
        flash(f'Successfully downloaded in {selected_quality["name"]}. {cost} credits deducted. Remaining credits: {current_user.credits}', 'success')
        img_io = io.BytesIO(); resized_img.save(img_io, 'PNG'); img_io.seek(0)
        return send_file(img_io, mimetype='image/png', as_attachment=True, download_name=f'{os.path.splitext(filename)[0]}_{quality}.png')
    except Exception as e:
        flash(f'An error occurred during download: {e}', 'danger')
        return redirect(url_for('remove_bg'))

@app.route('/pricing')
@login_required
def pricing(): return render_template('pricing.html')

# =================================================================
# 7. تشغيل التطبيق
# =================================================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
