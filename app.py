from flask import Flask, flash, render_template, request, redirect, session, url_for, jsonify
from models import *
from peewee import DoesNotExist
import bcrypt
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def setup_database():
    """Initialize database connection and create tables if they don't exist"""
    try:
        if not db.is_closed():
            db.close()
        db.connect()
        # Create tables if they don't exist
        db.create_tables([User, Student, Class, Attendance], safe=True)
    except Exception as e:
        print(f"Database setup error: {e}")

def get_db_connection():
    """Get a fresh database connection"""
    if db.is_closed():
        db.connect()
    return db

def close_db_connection():
    """Safely close database connection"""
    if not db.is_closed():
        db.close()

# Setup database on app start
setup_database()

# Ensure database connection is closed after each request
@app.teardown_appcontext
def close_db(error):
    close_db_connection()

# Ensure database connection before each request
@app.before_request
def before_request():
    get_db_connection()

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(plain_password, stored_password):
    # Handle both plain text and hashed passwords
    try:
        # Check if the stored password looks like a bcrypt hash
        if stored_password.startswith('$2b$') or stored_password.startswith('$2a$') or stored_password.startswith('$2y$'):
            # It's a bcrypt hash
            return bcrypt.checkpw(plain_password.encode('utf-8'), stored_password.encode('utf-8'))
        else:
            # Fall back to plain text comparison for backwards compatibility
            return plain_password == stored_password
    except Exception as e:
        print(f"Password check error: {e}")
        # If bcrypt fails, try plain text as fallback
        return plain_password == stored_password

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot-password.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        email = data.get('email')
        password = data.get('password')
        role = data.get('perfil')

        if not email or not password or not role:
            if request.is_json:
                return jsonify({'success': False, 'message': 'All fields are required'})
            flash("All fields are required.")
            return redirect(url_for('login'))

        try:
            get_db_connection()
            
            if role == 'admin':
                # Check in User table for admin
                user = User.get((User.Email == email) & (User.is_admin == 1))
                
                if check_password(password, user.Password):
                    session['user_id'] = user.UserID
                    session['user_name'] = user.Name
                    session['user_role'] = 'admin'
                    session['is_admin'] = True
                    
                    if request.is_json:
                        return jsonify({'success': True, 'redirect': '/admin'})
                    return redirect('/admin')
                else:
                    raise Exception("Invalid password")
                    
            elif role == 'teacher':
                # Check in User table for teacher (non-admin)
                user = User.get((User.Email == email) & (User.is_admin == 0))
                
                if check_password(password, user.Password):
                    session['user_id'] = user.UserID
                    session['user_name'] = user.Name
                    session['user_role'] = 'teacher'
                    session['is_admin'] = False
                    
                    if request.is_json:
                        return jsonify({'success': True, 'redirect': '/teacher'})
                    return redirect('/teacher')
                else:
                    raise Exception("Invalid password")
                    
            elif role == 'student':
                # Check in Student table
                student = Student.get(Student.Email == email)
                
                if check_password(password, student.Password):
                    session['user_id'] = student.StudentID
                    session['user_name'] = student.Name
                    session['user_role'] = 'student'
                    session['is_admin'] = False
                    
                    if request.is_json:
                        return jsonify({'success': True, 'redirect': '/student'})
                    return redirect('/student')
                else:
                    raise Exception("Invalid password")
                    
        except DoesNotExist:
            message = f"No {role} account found with this email."
            if request.is_json:
                return jsonify({'success': False, 'message': message})
            flash(message)
            return redirect(url_for('login'))
        except Exception as e:
            message = "Invalid credentials."
            if request.is_json:
                return jsonify({'success': False, 'message': message})
            flash(message)
            return redirect(url_for('login'))

    return render_template('email_e_password.html')

@app.route('/admin')
def admin():
    if 'user_role' not in session or session['user_role'] != 'admin':
        flash("Access denied. Admin privileges required.")
        return redirect(url_for('login'))
    return render_template('admin.html')

@app.route('/teacher')
def teacher():
    if 'user_role' not in session or session['user_role'] != 'teacher':
        flash("Access denied. Teacher privileges required.")
        return redirect(url_for('login'))
    return render_template('teacher.html')

@app.route('/student')
def student():
    if 'user_role' not in session or session['user_role'] != 'student':
        flash("Access denied. Student privileges required.")
        return redirect(url_for('login'))
    return render_template('student.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully.")
    return redirect(url_for('index'))

# API Routes for Admin functionality
@app.route('/api/admin/add-class', methods=['POST'])
def add_class():
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    data = request.get_json()
    try:
        get_db_connection()
        
        teacher_id = data.get('teacher_id')
        
        # Verify teacher exists and is not an admin
        teacher = User.get((User.UserID == teacher_id) & (User.is_admin == 0))
        
        Class.create(
            UserID=teacher.UserID,
            Title=data.get('classname'),
            ClassDate=data.get('classdate'),
            ClassTime=data.get('classtime')
        )
        return jsonify({'success': True, 'message': 'Class added successfully'})
    except DoesNotExist:
        return jsonify({'success': False, 'message': 'Teacher not found'})
    except Exception as e:
        print(f"Add class error: {e}")
        return jsonify({'success': False, 'message': 'Error adding class. Please try again.'})

@app.route('/api/admin/add-teacher', methods=['POST'])
def add_teacher():
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    data = request.get_json()
    try:
        get_db_connection()
        
        # Validate required fields
        name = data.get('teachername')
        email = data.get('teacheremail')
        password = data.get('teacherpassword')
        
        if not name or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        # Check if email already exists in User table
        existing_user = User.select().where(User.Email == email).exists()
        if existing_user:
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        # Check if email already exists in Student table
        existing_student = Student.select().where(Student.Email == email).exists()
        if existing_student:
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        # Validate password
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
        
        User.create(
            Name=name,
            Email=email,
            Password=hash_password(password),
            is_admin=0
        )
        return jsonify({'success': True, 'message': 'Teacher added successfully'})
    except Exception as e:
        print(f"Add teacher error: {e}")
        return jsonify({'success': False, 'message': 'Error adding teacher. Please try again.'})

@app.route('/api/admin/add-student', methods=['POST'])
def add_student():
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    data = request.get_json()
    try:
        get_db_connection()
        
        # Validate required fields
        name = data.get('studentname')
        email = data.get('studentemail')
        password = data.get('studentpassword')
        
        if not name or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'})
        
        # Check if email already exists in Student table
        existing_student = Student.select().where(Student.Email == email).exists()
        if existing_student:
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        # Check if email already exists in User table
        existing_user = User.select().where(User.Email == email).exists()
        if existing_user:
            return jsonify({'success': False, 'message': 'Email already exists'})
        
        # Validate password
        if len(password) < 6:
            return jsonify({'success': False, 'message': 'Password must be at least 6 characters long'})
        
        Student.create(
            Name=name,
            Email=email,
            Password=hash_password(password)
        )
        return jsonify({'success': True, 'message': 'Student added successfully'})
    except Exception as e:
        print(f"Add student error: {e}")
        return jsonify({'success': False, 'message': 'Error adding student. Please try again.'})

@app.route('/api/admin/teachers')
def get_teachers():
    if 'user_role' not in session or session['user_role'] != 'admin':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        get_db_connection()
        
        teachers = User.select().where(User.is_admin == 0)
        teachers_data = []
        for teacher in teachers:
            teachers_data.append({
                'id': teacher.UserID,
                'name': teacher.Name,
                'email': teacher.Email
            })
        return jsonify({'success': True, 'teachers': teachers_data})
    except Exception as e:
        print(f"Get teachers error: {e}")
        return jsonify({'success': False, 'message': 'Error loading teachers'})

# API Routes for Teacher functionality
@app.route('/api/teacher/classes')
def get_teacher_classes():
    if 'user_role' not in session or session['user_role'] != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        get_db_connection()
        
        classes = Class.select().where(Class.UserID == session['user_id'])
        classes_data = []
        for cls in classes:
            classes_data.append({
                'id': cls.ClassID,
                'title': cls.Title,
                'date': cls.ClassDate,
                'time': cls.ClassTime
            })
        return jsonify({'success': True, 'classes': classes_data})
    except Exception as e:
        print(f"Get teacher classes error: {e}")
        return jsonify({'success': False, 'message': 'Error loading classes'})

@app.route('/api/teacher/attendance', methods=['POST'])
def save_attendance():
    if 'user_role' not in session or session['user_role'] != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    data = request.get_json()
    try:
        get_db_connection()
        
        class_id = data.get('class_id')
        present_students = data.get('present_students', [])
        
        # Delete existing attendance for this class
        Attendance.delete().where(Attendance.ClassID == class_id).execute()
        
        # Add new attendance records
        for student_id in present_students:
            Attendance.create(
                ClassID=class_id,
                StudentID=student_id,
                attend=1
            )
        
        return jsonify({'success': True, 'message': 'Attendance saved successfully'})
    except Exception as e:
        print(f"Save attendance error: {e}")
        return jsonify({'success': False, 'message': 'Error saving attendance'})

@app.route('/api/teacher/students')
def get_students():
    if 'user_role' not in session or session['user_role'] != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        get_db_connection()
        
        students = Student.select()
        students_data = []
        for student in students:
            students_data.append({
                'id': student.StudentID,
                'name': student.Name,
                'email': student.Email
            })
        return jsonify({'success': True, 'students': students_data})
    except Exception as e:
        print(f"Get students error: {e}")
        return jsonify({'success': False, 'message': 'Error loading students'})

@app.route('/api/teacher/class-attendance/<int:class_id>')
def get_class_attendance(class_id):
    if 'user_role' not in session or session['user_role'] != 'teacher':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        get_db_connection()
        
        # Verify the class belongs to the current teacher
        class_obj = Class.get((Class.ClassID == class_id) & (Class.UserID == session['user_id']))
        
        # Get attendance records for this class
        attendance_records = Attendance.select().where(Attendance.ClassID == class_id)
        present_students = [att.StudentID.StudentID for att in attendance_records if att.attend == 1]
        
        return jsonify({'success': True, 'present_students': present_students})
    except DoesNotExist:
        return jsonify({'success': False, 'message': 'Class not found or access denied'})
    except Exception as e:
        print(f"Get class attendance error: {e}")
        return jsonify({'success': False, 'message': 'Error loading attendance'})

# API Routes for Student functionality
@app.route('/api/student/classes')
def get_student_classes():
    if 'user_role' not in session or session['user_role'] != 'student':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        get_db_connection()
        
        # For now, return all classes (you might want to implement enrollment)
        classes = Class.select()
        classes_data = []
        for cls in classes:
            classes_data.append({
                'id': cls.ClassID,
                'title': cls.Title,
                'date': cls.ClassDate,
                'time': cls.ClassTime
            })
        return jsonify({'success': True, 'classes': classes_data})
    except Exception as e:
        print(f"Get student classes error: {e}")
        return jsonify({'success': False, 'message': 'Error loading classes'})

@app.route('/api/student/attendance')
def get_student_attendance():
    if 'user_role' not in session or session['user_role'] != 'student':
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        get_db_connection()
        
        student_id = session['user_id']
        attendance = Attendance.select().where(Attendance.StudentID == student_id)
        attendance_data = []
        for att in attendance:
            attendance_data.append({
                'class_id': att.ClassID.ClassID,
                'class_title': att.ClassID.Title,
                'attended': att.attend
            })
        return jsonify({'success': True, 'attendance': attendance_data})
    except Exception as e:
        print(f"Get student attendance error: {e}")
        return jsonify({'success': False, 'message': 'Error loading attendance'})


if __name__ == '__main__':
    app.run(debug=True)
