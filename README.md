# Mr-Nizar-English-Exam-Preparation-Platform
MR Nizar Platform
# COMPLETE COMPREHENSIVE CODE FOR THE EDUCATIONAL PLATFORM
# "برنامج رفع نتائج امتحان اللغة الإنجليزية"
# Developed and created by Mr. Nizar BenAli
# Flask Web App + Interactive Quizzes + File Uploads + Role-Based Access
# Features: Teacher/Admin control, Student progress, Parent view, Grammar Library, Exams, Personalized Exercises, Reports

# REQUIREMENTS (install via pip):
# flask flask-sqlalchemy flask-login flask-security-too werkzeug python-dotenv

import os
import json
import random
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_login.mixins import UserMixin
from flask_security import Security, SQLAlchemyUserDatastore, roles_accepted, RoleMixin
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super_secret_key_change_in_production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///english_platform.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'docx', 'txt', 'jpg', 'png'}

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'signin'

# Roles-Users association
roles_users = db.Table('roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)

# Models
class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(150))
    active = db.Column(db.Boolean, default=True)
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    # For parent-student linking (simple)
    parent_of = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

class Program(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), default="English Exam Improvement Program – 6 Weeks")
    week = db.Column(db.Integer)  # 1 to 6
    description = db.Column(db.Text)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Lesson(db.Model):  # Grammar Library
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)  # e.g., Tenses, Conditionals
    title = db.Column(db.String(200))
    explanation = db.Column(db.Text)
    examples = db.Column(db.Text)
    worksheet_path = db.Column(db.String(255))

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    quiz_type = db.Column(db.String(100))  # Diagnostic, Mock, Grammar, etc.
    questions_json = db.Column(db.Text, nullable=False)  # JSON list of questions
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Quiz assignment (many-to-many + results)
quiz_assignment = db.Table('quiz_assignment',
    db.Column('quiz_id', db.Integer, db.ForeignKey('quiz.id'), primary_key=True),
    db.Column('student_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('score', db.Float, default=0.0),
    db.Column('completed', db.Boolean, default=False),
    db.Column('submitted_answers', db.Text),
    db.Column('submitted_at', db.DateTime)
)

class Exercise(db.Model):  # Personalized AI-supported
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    file_path = db.Column(db.String(255))
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    content = db.Column(db.Text)
    file_path = db.Column(db.String(255))
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Security setup
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        name = request.form['name']
        role_name = request.form['role']
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('signup'))
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            flash('Invalid role')
            return redirect(url_for('signup'))
        user = User(email=email, password=password, name=name)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please sign in.')
        return redirect(url_for('signin'))
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('signin.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.has_role('Teacher'):
        students = User.query.filter(User.roles.any(Role.name == 'Student')).all()
        quizzes = Quiz.query.all()
        return render_template('teacher_dashboard.html', students=students, quizzes=quizzes)
    elif current_user.has_role('Student'):
        assigned_quizzes = db.session.query(Quiz).join(quiz_assignment).filter(quiz_assignment.c.student_id == current_user.id).all()
        programs = Program.query.filter_by(student_id=current_user.id).all()
        exercises = Exercise.query.filter_by(student_id=current_user.id).all()
        return render_template('student_dashboard.html', quizzes=assigned_quizzes, programs=programs, exercises=exercises)
    elif current_user.has_role('Parent'):
        # Simple: find linked student
        student = User.query.filter_by(parent_of=current_user.id).first()
        reports = Report.query.filter_by(student_id=student.id if student else None).all() if student else []
        return render_template('parent_dashboard.html', reports=reports)
    return "Unauthorized"

# Grammar Library
@app.route('/grammar')
@login_required
@roles_accepted('Teacher', 'Student')
def grammar():
    lessons = Lesson.query.all()
    return render_template('grammar.html', lessons=lessons)

# Quiz Management
@app.route('/create_quiz', methods=['GET', 'POST'])
@login_required
@roles_accepted('Teacher')
def create_quiz():
    if request.method == 'POST':
        title = request.form['title']
        quiz_type = request.form['quiz_type']
        questions_json = request.form['questions_json']
        try:
            questions = json.loads(questions_json)
        except:
            flash('Invalid JSON for questions')
            return redirect(url_for('create_quiz'))
        quiz = Quiz(title=title, quiz_type=quiz_type, questions_json=json.dumps(questions), created_by=current_user.id)
        db.session.add(quiz)
        db.session.commit()
        flash('Quiz created!')
        return redirect(url_for('dashboard'))
    return render_template('create_quiz.html')

@app.route('/assign_quiz/<int:quiz_id>', methods=['POST'])
@login_required
@roles_accepted('Teacher')
def assign_quiz(quiz_id):
    student_ids = request.form.getlist('students')
    for sid in student_ids:
        assignment = quiz_assignment.insert().values(quiz_id=quiz_id, student_id=sid)
        db.session.execute(assignment)
    db.session.commit()
    flash('Quiz assigned!')
    return redirect(url_for('dashboard'))

@app.route('/take_quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
@roles_accepted('Student')
def take_quiz(quiz_id):
    assignment = db.session.query(quiz_assignment).filter_by(quiz_id=quiz_id, student_id=current_user.id).first()
    if not assignment or assignment.c.completed:
        abort(403)
    quiz = Quiz.query.get_or_404(quiz_id)
    questions = json.loads(quiz.questions_json)

    if request.method == 'POST':
        score = 0
        total = len(questions)
        answers = {}
        for q in questions:
            qid = str(q['id'])
            user_ans = request.form.get(qid)
            answers[qid] = user_ans
            if q['type'] == 'multiple_choice' and int(user_ans) == q['correct']:
                score += 1
            elif q['type'] in ['fill_blank', 'true_false'] and user_ans.strip().lower() == str(q['correct']).lower():
                score += 1
        percentage = (score / total) * 100 if total else 0
        db.session.execute(
            quiz_assignment.update()
            .where(quiz_assignment.c.quiz_id == quiz_id)
            .where(quiz_assignment.c.student_id == current_user.id)
            .values(score=percentage, completed=True, submitted_answers=json.dumps(answers), submitted_at=datetime.utcnow())
        )
        db.session.commit()
        flash(f'Quiz submitted! Score: {score}/{total} ({percentage:.1f}%)')
        return redirect(url_for('dashboard'))

    # Shuffle options
    for q in questions:
        if q['type'] == 'multiple_choice':
            opts = list(enumerate(q['options']))
            random.shuffle(opts)
            q['shuffled'] = [o for _, o in opts]
            q['correct_shuffled'] = next(i for i, (_, o) in enumerate(opts) if i == q['correct'])
    return render_template('take_quiz.html', quiz=quiz, questions=questions)

@app.route('/quiz_results/<int:quiz_id>')
@login_required
@roles_accepted('Teacher')
def quiz_results(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    results = db.session.query(quiz_assignment, User).join(User).filter(quiz_assignment.c.quiz_id == quiz_id).all()
    return render_template('quiz_results.html', quiz=quiz, results=results)

# File Uploads (Lessons, Exercises, Reports)
@app.route('/upload/<entity>', methods=['POST'])
@login_required
@roles_accepted('Teacher')
def upload_file(entity):
    if 'file' not in request.files:
        flash('No file')
        return redirect(request.referrer or url_for('dashboard'))
    file = request.files['file']
    if file.filename == '' or not allowed_file(file.filename):
        flash('Invalid file')
        return redirect(request.referrer or url_for('dashboard'))
    filename = secure_filename(file.filename)
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    if entity == 'lesson':
        lesson = Lesson(title=request.form['title'], category=request.form['category'], worksheet_path=filename)
        db.session.add(lesson)
    elif entity == 'exercise':
        exercise = Exercise(title=request.form['title'], file_path=filename, student_id=request.form['student_id'])
        db.session.add(exercise)
    elif entity == 'report':
        report = Report(title=request.form['title'], file_path=filename, student_id=request.form['student_id'])
        db.session.add(report)
    db.session.commit()
    flash('File uploaded')
    return redirect(url_for('dashboard'))

@app.route('/downloads/<filename>')
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Admin: Add Program
@app.route('/add_program', methods=['POST'])
@login_required
@roles_accepted('Teacher')
def add_program():
    student_id = request.form['student_id']
    for week in range(1, 7):
        program = Program(week=week, description=f"Week {week} content", student_id=student_id)
        db.session.add(program)
    db.session.commit()
    flash('Program assigned to student')
    return redirect(url_for('dashboard'))

# Run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create roles if not exist
        for role_name in ['Teacher', 'Student', 'Parent']:
            if not Role.query.filter_by(name=role_name).first():
                db.session.add(Role(name=role_name))
        db.session.commit()
    app.run(debug=True)
    <!-- templates/index.html -->
<!doctype html>
<html>
<head><title>Welcome - Developed by Mr. Nizar BenAli</title></head>
<body>
<h1>Welcome to برنامج رفع نتائج امتحان اللغة الإنجليزية</h1>
<p>Developed and created by Mr. Nizar BenAli</p>
<a href="/signup">Sign Up</a> | <a href="/signin">Sign In</a>
</body>
</html>
<!-- templates/signup.html -->
<form method="POST">
    Name: <input name="name"><br>
    Email: <input name="email"><br>
    Password: <input type="password" name="password"><br>
    Role: <select name="role">
        <option>Teacher</option>
        <option>Student</option>
        <option>Parent</option>
    </select><br>
    <button>Sign Up</button>
</form>
<!-- templates/signin.html -->
<form method="POST">
    Email: <input name="email"><br>
    Password: <input type="password" name="password"><br>
    <button>Sign In</button>
</form>
<!-- templates/teacher_dashboard.html -->
<h1>Teacher Dashboard</h1>
<p>Welcome, {{ current_user.name }}</p>
<h2>Students</h2>
<ul>
{% for s in students %}
    <li>{{ s.name }} ({{ s.email }})</li>
{% endfor %}
</ul>
<h2>Quizzes</h2>
<ul>
{% for q in quizzes %}
    <li><a href="/quiz_results/{{ q.id }}">{{ q.title }}</a></li>
{% endfor %}
</ul>
<!-- Forms for uploads, assign quizzes, etc. -->
<!-- templates/student_dashboard.html -->
<h1>Student Dashboard</h1>
<h2>Assigned Quizzes</h2>
<ul>
{% for q in quizzes %}
    <li><a href="/take_quiz/{{ q.id }}">{{ q.title }}</a></li>
{% endfor %}
</ul>
<h2>Programs</h2>
<ul>
{% for p in programs %}
    <li>Week {{ p.week }}: {{ p.description }}</li>
{% endfor %}
</ul>
<h2>Personalized Exercises</h2>
<ul>
{% for e in exercises %}
    <li>{{ e.title }} <a href="/downloads/{{ e.file_path }}">Download</a></li>
{% endfor %}
</ul>
<!-- templates/parent_dashboard.html -->
<h1>Parent Dashboard</h1>
<h2>Reports</h2>
<ul>
{% for r in reports %}
    <li>{{ r.title }} ({{ r.created_at }}) <a href="/downloads/{{ r.file_path }}">View</a></li>
{% endfor %}
</ul>
<!-- templates/grammar.html -->
<h1>Grammar Library</h1>
<ul>
{% for l in lessons %}
    <li>{{ l.category }}: {{ l.title }} <a href="/downloads/{{ l.worksheet_path }}">Worksheet</a></li>
{% endfor %}
</ul>
<!-- templates/create_quiz.html -->
<h1>Create Quiz</h1>
<form method="POST">
    Title: <input name="title"><br>
    Type: <input name="quiz_type"><br>
    Questions JSON: <textarea name="questions_json"></textarea><br>
    <button>Submit</button>
</form>
<!-- templates/take_quiz.html -->
<h1>{{ quiz.title }}</h1>
<form method="POST">
{% for q in questions %}
    <p>{{ q.question }}</p>
    {% if q.type == 'multiple_choice' %}
        {% for i, opt in enumerate(q.shuffled or q.options) %}
            <input type="radio" name="{{ q.id }}" value="{{ i }}"> {{ opt }}<br>
        {% endfor %}
    {% elif q.type == 'fill_blank' %}
        <input type="text" name="{{ q.id }}">
    {% endif %}
{% endfor %}
<button>Submit</button>
</form>
<!-- templates/quiz_results.html -->
<h1>{{ quiz.title }} Results</h1>
<ul>
{% for r in results %}
    <li>{{ r.User.name }}: Score {{ r.quiz_assignment.score }}% (Completed: {{ r.quiz_assignment.completed }})</li>
{% endfor %}
</ul>
# COMPLETE CODE UPDATE: AI QUIZ GENERATION ADDED
# "برنامج رفع نتائج امتحان اللغة الإنجليزية"
# Developed and created by Mr. Nizar BenAli
# Now with AI-powered quiz generation using Grok API (or fallback simulation)

# NEW DEPENDENCIES: Add to requirements
# requests

import requests
import json
import random
from datetime import datetime

# ... (all previous imports and code remain the same until the new section)

# NEW CONFIG: Add your Grok API key (get from https://grok.x.ai/api)
GROK_API_KEY = "your_grok_api_key_here"  # Mr. Nizar BenAli: Replace with your actual key
GROK_API_URL = "https://api.x.ai/v1/chat/completions"

# Fallback sample questions if API not available (for demo/testing)
FALLBACK_QUESTIONS = {
    "tenses": [
        {"id": 1, "type": "multiple_choice", "question": "She _____ football every weekend.", "options": ["play", "plays", "playing", "is play"], "correct": 1},
        {"id": 2, "type": "fill_blank", "question": "Right now, I _____ (study) English.", "correct": "am studying"},
        {"id": 3, "type": "multiple_choice", "question": "Yesterday, they _____ (go) to the cinema.", "options": ["go", "goes", "went", "gone"], "correct": 2}
    ],
    "conditionals": [
        {"id": 1, "type": "multiple_choice", "question": "If it rains tomorrow, we _____ at home.", "options": ["stay", "stays", "will stay", "stayed"], "correct": 2},
        {"id": 2, "type": "multiple_choice", "question": "If I were rich, I _____ around the world.", "options": ["travel", "travels", "will travel", "would travel"], "correct": 3}
    ],
    "passive_voice": [
        {"id": 1, "type": "multiple_choice", "question": "The room _____ every day.", "options": ["cleans", "is cleaned", "cleaned", "cleaning"], "correct": 1},
        {"id": 2, "type": "fill_blank", "question": "English _____ (speak) in many countries.", "correct": "is spoken"}
    ],
    "reported_speech": [
        {"id": 1, "type": "multiple_choice", "question": 'She said, "I am tired." → She said that she _____ tired.', "options": ["is", "was", "has been", "will be"], "correct": 1},
        {"id": 2, "type": "fill_blank", "question": '"Don\'t run!" the teacher said. → The teacher told us _____ run.', "correct": "not to"}
    ]
}

# NEW FUNCTION: AI Quiz Generation
def generate_ai_quiz(topic: str, num_questions: int = 8, level: str = "middle_secondary"):
    """
    Calls Grok API to generate quiz questions on the given topic.
    Returns list of questions in standardized format.
    """
    prompt = f"""
    You are an expert English teacher with 20 years of experience.
    Create exactly {num_questions} high-quality exam-style questions for middle/secondary school students.
    Topic: {topic}
    Level: {level}
    
    Include a mix of:
    - Multiple choice (4 options, one correct)
    - Fill in the blank
    - True/False (optional)
    
    Focus on common exam mistakes and key grammar/vocabulary points.
    
    Output ONLY valid JSON in this exact format (no extra text):
    [
      {{
        "id": 1,
        "type": "multiple_choice",
        "question": "Question text here",
        "options": ["A", "B", "C", "D"],
        "correct": 0  // 0-based index of correct option
      }},
      {{
        "id": 2,
        "type": "fill_blank",
        "question": "Fill in: Water _____ (boil) at 100°C.",
        "correct": "boils"
      }}
    ]
    """

    headers = {
        "Authorization": f"Bearer {GROK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "grok-beta",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.7,
        "max_tokens": 2000
    }

    try:
        response = requests.post(GROK_API_URL, headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            content = response.json()['choices'][0]['message']['content']
            # Extract JSON from response (in case of extra text)
            start = content.find('[')
            end = content.rfind(']') + 1
            if start != -1 and end > start:
                questions = json.loads(content[start:end])
                return questions
            else:
                flash("AI response not in JSON format. Using fallback.")
        else:
            flash(f"API Error {response.status_code}. Using fallback.")
    except Exception as e:
        flash(f"AI connection failed: {str(e)}. Using fallback.")

    # Fallback to pre-defined questions
    key = topic.lower().replace(" ", "_")
    questions = FALLBACK_QUESTIONS.get(key, FALLBACK_QUESTIONS["tenses"])
    # Random sample to match requested number
    return random.sample(questions * 3, min(num_questions, len(questions * 3)))

# NEW ROUTE: AI Quiz Generation Page
@app.route('/ai_generate_quiz', methods=['GET', 'POST'])
@login_required
@roles_accepted('Teacher')
def ai_generate_quiz():
    generated_questions = None
    if request.method == 'POST':
        topic = request.form['topic']
        num_questions = int(request.form.get('num_questions', 8))
        level = request.form['level']
        title = request.form['title']

        questions = generate_ai_quiz(topic, num_questions, level)

        # Optionally save directly
        if 'save' in request.form:
            quiz = Quiz(
                title=title or f"AI-Generated: {topic.capitalize()}",
                quiz_type="AI_Generated",
                questions_json=json.dumps(questions),
                created_by=current_user.id
            )
            db.session.add(quiz)
            db.session.commit()
            flash('AI quiz generated and saved successfully!')
            return redirect(url_for('dashboard'))

        generated_questions = questions

    return render_template('ai_generate_quiz.html', questions=generated_questions)

# NEW TEMPLATE: ai_generate_quiz.html
<!-- templates/ai_generate_quiz.html -->
<!doctype html>
<html>
<head>
    <title>AI Quiz Generator - By Mr. Nizar BenAli</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        textarea { width: 100%; height: 400px; }
    </style>
</head>
<body>
    <h1>AI Quiz Generator</h1>
    <p>Developed by Mr. Nizar BenAli</p>
    <p>Generate high-quality English exam questions using AI instantly.</p>

    <form method="POST">
        <label>Quiz Title:</label><br>
        <input type="text" name="title" placeholder="e.g., Week 3 Grammar Practice" style="width:100%"><br><br>

        <label>Topic (e.g., Present Tenses, Conditionals, Reported Speech):</label><br>
        <input type="text" name="topic" required style="width:100%"><br><br>

        <label>Number of Questions:</label>
        <select name="num_questions">
            <option>5</option>
            <option selected>8</option>
            <option>10</option>
            <option>12</option>
        </select><br><br>

        <label>Level:</label>
        <select name="level">
            <option>middle_secondary</option>
            <option>secondary_advanced</option>
        </select><b
        r><br>

        <button type="submit" name="action" value="preview">Preview Questions</button>
        <button type="submit" name="save">Generate & Save Quiz</button>
    </form>

    {% if questions %}
        <h2>Generated Questions ({{ questions|length }})</h2>
        <pre>{{ json.dumps(questions, indent=2) }}</pre>
        <p><strong>Copy the JSON above and paste in Create Quiz page, or click "Generate & Save" next time.</strong></p>
    {% endif %}

    <br><a href="/dashboard">← Back to Dashboard</a>
</body>
</html>
