from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

DB_FILE = '1st_year.db'

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Needed for session management

# --------------------
# STEP 1: Database Connection & Structure Setup
# --------------------
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # Create users table first (STEP 1: Database Structure)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create bookmarks table with proper foreign key relationships (STEP 1)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            topic TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, question_id)
        )
    ''')
    
    # Create topic_completion table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS topic_completion (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            topic TEXT NOT NULL,
            completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create user_notes table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS user_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            question_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Add is_premium column to qbank table for access control
    try:
        conn.execute('ALTER TABLE qbank ADD COLUMN is_premium INTEGER DEFAULT 1')
        conn.commit()
        print("Added is_premium column to qbank table")
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
    conn.commit()
    conn.close()

# Initialize database when app starts
with app.app_context():
    init_db()

# --------------------
# NEW: Free Content Management Functions (CORRECTED LOGIC)
# --------------------
def setup_free_content():
    """Mark specific topics as free access - all others require login"""
    # Topics that DON'T require login (free content for everyone)
    free_topics = [
        ('Anatomy', 'Basic Anatomy'),
        ('Anatomy', 'General Anatomy'),
        ('Physiology', 'Basic Physiology'),
        ('Physiology', 'Cardiovascular System'),
        ('Biochemistry', 'Carbohydrates'),
        ('Biochemistry', 'Proteins'),
        ('Pathology', 'General Pathology'),
        ('Pathology', 'Cell Injury'),
        ('Pharmacology', 'General Pharmacology'),
        ('Pharmacology', 'Basic Pharmacokinetics')
    ]
    
    conn = get_db_connection()
    try:
        # First, mark ALL topics as requiring login (premium = 1)
        conn.execute('UPDATE qbank SET is_premium = 1')
        
        # Then mark only specific topics as free (premium = 0)
        for subject, topic in free_topics:
            conn.execute('''
                UPDATE qbank 
                SET is_premium = 0 
                WHERE LOWER(subject) = ? AND LOWER(topic) = ?
            ''', (subject.lower(), topic.lower()))
        
        conn.commit()
        print(f"Content setup completed. {len(free_topics)} topics are free, all others require login.")
        return True
    except Exception as e:
        print(f"Error setting up content access: {e}")
        return False
    finally:
        conn.close()

def is_topic_login_required(subject, topic):
    """Check if a topic requires user login (returns True if login required)"""
    conn = get_db_connection()
    try:
        result = conn.execute('''
            SELECT DISTINCT is_premium 
            FROM qbank 
            WHERE LOWER(subject) = ? AND LOWER(topic) = ?
            LIMIT 1
        ''', (subject.lower(), topic.lower())).fetchone()
        
        # If is_premium = 1, login is required
        # If is_premium = 0, topic is free
        return result and result['is_premium'] == 1
    finally:
        conn.close()

def mark_topic_as_login_required(subject, topic):
    """Mark a specific topic as requiring login (admin function)"""
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE qbank 
            SET is_premium = 1 
            WHERE LOWER(subject) = ? AND LOWER(topic) = ?
        ''', (subject.lower(), topic.lower()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking topic as login required: {e}")
        return False
    finally:
        conn.close()

def mark_topic_as_free(subject, topic):
    """Mark a specific topic as free access (admin function)"""
    conn = get_db_connection()
    try:
        conn.execute('''
            UPDATE qbank 
            SET is_premium = 0 
            WHERE LOWER(subject) = ? AND LOWER(topic) = ?
        ''', (subject.lower(), topic.lower()))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error marking topic as free: {e}")
        return False
    finally:
        conn.close()

# --------------------
# STEP 2: User Session Management Functions
# --------------------
def ensure_user_session():
    """Validate user session exists and return user_id"""
    if 'user_id' not in session:
        return None
    return session['user_id']

def create_user_session(user_id, username):
    """Create user session after login"""
    session['user_id'] = user_id
    session['username'] = username
    session.permanent = True  # Make session persistent

# --------------------
# Helper Functions
# --------------------
def get_question_count(conn, subject_name, topic_name):
    """Get the count of questions for a specific topic"""
    result = conn.execute(
        'SELECT COUNT(*) as count FROM qbank WHERE LOWER(subject) = ? AND topic = ?',
        (subject_name.lower(), topic_name)
    ).fetchone()
    return result['count'] if result else 0

def is_bookmarked(conn, user_id, question_id):
    """Check if a question is bookmarked by user (STEP 2: Session Check)"""
    if not user_id:
        return False
    result = conn.execute(
        'SELECT id FROM bookmarks WHERE user_id = ? AND question_id = ?',
        (user_id, question_id)
    ).fetchone()
    return result is not None

def is_topic_completed(conn, user_id, subject, topic):
    """Check if a topic is completed by user"""
    if not user_id:
        return False
    result = conn.execute(
        'SELECT id FROM topic_completion WHERE user_id = ? AND LOWER(subject) = ? AND topic = ?',
        (user_id, subject.lower(), topic)
    ).fetchone()
    return result is not None

def get_user_note(conn, user_id, question_id):
    """Get user's note for a question"""
    if not user_id:
        return None
    result = conn.execute(
        'SELECT note FROM user_notes WHERE user_id = ? AND question_id = ?',
        (user_id, question_id)
    ).fetchone()
    return result['note'] if result else None

def get_next_topic(conn, subject_name, current_topic):
    """Get the next topic in the same subject"""
    topics = conn.execute(
        '''
        SELECT DISTINCT topic 
        FROM qbank 
        WHERE LOWER(subject) = ? AND topic != "" 
        ORDER BY topic
        ''',
        (subject_name.lower(),)
    ).fetchall()
    
    topic_list = [t['topic'] for t in topics]
    try:
        current_index = topic_list.index(current_topic)
        if current_index < len(topic_list) - 1:
            return topic_list[current_index + 1]
    except ValueError:
        pass
    return None

# --------------------
# STEP 5: Database Operations Functions
# --------------------
def add_bookmark_to_db(user_id, question_id, subject, topic):
    """Add bookmark to database (STEP 5: Database Insert)"""
    conn = get_db_connection()
    try:
        conn.execute(
            'INSERT INTO bookmarks (user_id, question_id, subject, topic) VALUES (?, ?, ?, ?)',
            (user_id, question_id, subject, topic)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Bookmark already exists
        return False
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

def remove_bookmark_from_db(user_id, question_id):
    """Remove bookmark from database (STEP 5: Database Delete)"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM bookmarks WHERE user_id = ? AND question_id = ?',
            (user_id, question_id)
        )
        success = cursor.rowcount > 0  # Check if any row was deleted
        conn.commit()
        return success
    except Exception as e:
        print(f"Database error: {e}")
        return False
    finally:
        conn.close()

# --------------------
# STEP 4: Backend Route Processing (Flask Routes for Bookmark Addition)
# --------------------
@app.route('/toggle_bookmark', methods=['POST'])
def toggle_bookmark():
    """STEP 4: Backend Route Processing - Main bookmark toggle endpoint"""
    # STEP 2: Check user session (bookmarks require login)
    user_id = ensure_user_session()
    if not user_id:
        return jsonify({'success': False, 'message': 'Please login to bookmark questions'})
    
    try:
        # STEP 4: Get JSON data from request
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'No data received'})
        
        # STEP 4: Validate required fields
        question_id = data.get('question_id')
        subject = data.get('subject')
        topic = data.get('topic')
        
        if not all([question_id, subject, topic]):
            return jsonify({'success': False, 'message': 'Missing required data'})
        
        # STEP 4: Check if bookmark already exists
        conn = get_db_connection()
        existing = conn.execute(
            'SELECT id FROM bookmarks WHERE user_id = ? AND question_id = ?',
            (user_id, question_id)
        ).fetchone()
        conn.close()
        
        if existing:
            # STEP 5: Remove bookmark from database
            success = remove_bookmark_from_db(user_id, question_id)
            if success:
                return jsonify({
                    'success': True, 
                    'bookmarked': False, 
                    'message': 'Bookmark removed successfully'
                })
            else:
                return jsonify({'success': False, 'message': 'Failed to remove bookmark'})
        else:
            # STEP 5: Add bookmark to database
            success = add_bookmark_to_db(user_id, question_id, subject, topic)
            if success:
                return jsonify({
                    'success': True, 
                    'bookmarked': True, 
                    'message': 'Bookmark added successfully'
                })
            else:
                return jsonify({'success': False, 'message': 'Bookmark already exists or failed to add'})
                
    except Exception as e:
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

@app.route('/add_bookmark', methods=['POST'])
def add_bookmark():
    """Alternative route for adding bookmarks via form submission (STEP 2: Flask Route)"""
    user_id = ensure_user_session()
    if not user_id:
        flash('Please login to bookmark questions')
        return redirect(url_for('login'))
    
    # STEP 3: Get data from form
    question_id = request.form.get('question_id')
    subject = request.form.get('subject')
    topic = request.form.get('topic')
    
    # STEP 4: Validate input
    if not all([question_id, subject, topic]):
        flash('Missing required bookmark data')
        return redirect(request.referrer or url_for('home'))
    
    # STEP 5: Add to database
    success = add_bookmark_to_db(user_id, int(question_id), subject, topic)
    
    if success:
        flash('Question bookmarked successfully!')
    else:
        flash('Question is already bookmarked or error occurred')
    
    return redirect(request.referrer or url_for('home'))

# --------------------
# BOOKMARKS ROUTE - REQUIRES LOGIN
# --------------------
@app.route('/bookmarks')
def bookmarks():
    """Display all user bookmarks - Requires login"""
    user_id = ensure_user_session()
    if not user_id:
        flash('Please login to view your bookmarks')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        bookmarks = conn.execute('''
            SELECT b.id as bookmark_id,
                   b.question_id,
                   b.subject,
                   b.topic,
                   b.created_at,
                   q.question,
                   q.answer
            FROM bookmarks b
            JOIN qbank q ON b.question_id = q.id
            WHERE b.user_id = ?
            ORDER BY b.created_at DESC
        ''', (user_id,)).fetchall()
        
        return render_template('bookmarks.html', bookmarks=bookmarks)
            
    except Exception as e:
        flash(f'Error loading bookmarks: {str(e)}')
        return redirect(url_for('home'))
    finally:
        conn.close()

@app.route('/bookmarks/subject/<subject_name>')
def bookmarks_by_subject(subject_name):
    """Filter bookmarks by subject - Requires login"""
    user_id = ensure_user_session()
    if not user_id:
        flash('Please login first')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        bookmarks = conn.execute('''
            SELECT b.id as bookmark_id,
                   b.question_id,
                   b.subject,
                   b.topic,
                   b.created_at,
                   q.question,
                   q.answer
            FROM bookmarks b
            JOIN qbank q ON b.question_id = q.id
            WHERE b.user_id = ? AND LOWER(b.subject) = ?
            ORDER BY b.created_at DESC
        ''', (user_id, subject_name.lower())).fetchall()
        
        return render_template('bookmarks.html', 
                             bookmarks=bookmarks, 
                             filtered_subject=subject_name)
    finally:
        conn.close()

@app.route('/remove_bookmark/<int:bookmark_id>', methods=['POST'])
def remove_bookmark_by_id(bookmark_id):
    """Remove a specific bookmark by bookmark ID"""
    user_id = ensure_user_session()
    if not user_id:
        return jsonify({'success': False, 'message': 'Please login first'})
    
    conn = get_db_connection()
    try:
        # Verify bookmark belongs to user and get question_id
        bookmark = conn.execute(
            'SELECT question_id FROM bookmarks WHERE id = ? AND user_id = ?',
            (bookmark_id, user_id)
        ).fetchone()
        
        if not bookmark:
            return jsonify({'success': False, 'message': 'Bookmark not found'})
        
        # Remove bookmark using existing function
        success = remove_bookmark_from_db(user_id, bookmark['question_id'])
        
        if success:
            return jsonify({'success': True, 'message': 'Bookmark removed successfully'})
        else:
            return jsonify({'success': False, 'message': 'Failed to remove bookmark'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})
    finally:
        conn.close()

# --------------------
# Admin Routes for Content Management
# --------------------
@app.route('/admin/setup_content_access')
def admin_setup_content_access():
    """Admin route to setup content access - Only specific topics are free"""
    success = setup_free_content()
    if success:
        return "Content access setup completed. Only specific basic topics are free, all others require login. <a href='/home'>Back to Home</a>"
    else:
        return "Failed to setup content access. <a href='/home'>Back to Home</a>"

@app.route('/admin/require_login/<subject>/<topic>')
def admin_require_login(subject, topic):
    """Admin route to mark specific topic as requiring login"""
    success = mark_topic_as_login_required(subject, topic)
    if success:
        return f"Topic '{topic}' in '{subject}' now requires login. <a href='/home'>Back to Home</a>"
    else:
        return f"Failed to update topic access. <a href='/home'>Back to Home</a>"

@app.route('/admin/make_free/<subject>/<topic>')
def admin_make_free(subject, topic):
    """Admin route to mark specific topic as free access"""
    success = mark_topic_as_free(subject, topic)
    if success:
        return f"Topic '{topic}' in '{subject}' is now free for everyone. <a href='/home'>Back to Home</a>"
    else:
        return f"Failed to update topic access. <a href='/home'>Back to Home</a>"

# --------------------
# Topic Completion Routes (Requires Login)
# --------------------
@app.route('/complete_topic', methods=['POST'])
def complete_topic():
    user_id = ensure_user_session()
    if not user_id:
        return jsonify({'success': False, 'message': 'Please login to track progress'})
    
    try:
        data = request.get_json()
        subject = data.get('subject')
        topic = data.get('topic')
        
        conn = get_db_connection()
        
        # Check if already completed
        existing = conn.execute(
            'SELECT id FROM topic_completion WHERE user_id = ? AND LOWER(subject) = ? AND topic = ?',
            (user_id, subject.lower(), topic)
        ).fetchone()
        
        if not existing:
            conn.execute(
                'INSERT INTO topic_completion (user_id, subject, topic) VALUES (?, ?, ?)',
                (user_id, subject, topic)
            )
            conn.commit()
        
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# --------------------
# Notes Routes (Requires Login)
# --------------------
@app.route('/save_note', methods=['POST'])
def save_note():
    user_id = ensure_user_session()
    if not user_id:
        return jsonify({'success': False, 'message': 'Please login to save notes'})
    
    try:
        data = request.get_json()
        question_id = data.get('question_id')
        note = data.get('note', '').strip()
        
        conn = get_db_connection()
        
        if note:
            # Save or update note
            conn.execute('''
                INSERT OR REPLACE INTO user_notes (user_id, question_id, note, updated_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (user_id, question_id, note))
        else:
            # Delete note if empty
            conn.execute(
                'DELETE FROM user_notes WHERE user_id = ? AND question_id = ?',
                (user_id, question_id)
            )
        
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# --------------------
# Authentication Routes
# --------------------
@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # Check if user came from login-required content redirect
    from_restricted = request.args.get('restricted', False)
    
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']

        if not username or not email or not password:
            flash('Please fill all the fields.')
            return redirect(url_for('signup'))

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user:
            conn.close()
            flash('Email already registered.')
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                     (username, email, hashed_pw))
        conn.commit()
        conn.close()
        flash('Account created! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html', from_restricted=from_restricted)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username'].strip().lower()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            # STEP 2: Create user session
            create_user_session(user['id'], user['username'])
            flash(f'Welcome back, {user["username"]}!')
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('landing'))

# --------------------
# Main Application Routes (LIMITED FREE content, MOST require login)
# --------------------
@app.route('/home')
def home():
    """Home page - Accessible to everyone"""
    conn = get_db_connection()
    user_id = session.get('user_id')

    # Get distinct subjects from DB
    rows = conn.execute('SELECT DISTINCT subject FROM qbank ORDER BY subject').fetchall()
    db_subjects = {row['subject'].strip().lower() for row in rows if row['subject']}

    # Hardcoded MBBS Subject to Prof Year Mapping
    PROF_YEAR_MAP = {
        "1st Prof": ["Anatomy", "Physiology", "Biochemistry"],
        "2nd Prof": ["Pathology", "Microbiology", "Pharmacology", "Forensic Medicine"],
        "3rd Prof Part 1": ["PSM", "ENT", "Ophthalmology"],
        "3rd Prof Part 2": ["Medicine", "Surgery", "Pediatrics", "Obstetrics & Gynecology", 
                            "Orthopedics", "Dermatology", "Psychiatry", "Radiology"]
    }

    grouped_subjects = {}

    # Categorize existing DB subjects into prof years
    for year, subjects in PROF_YEAR_MAP.items():
        matched_subjects = []
        for subject in subjects:
            if subject.lower() in db_subjects:
                # Get completion status for this subject (only for logged-in users)
                completed_topics = 0
                total_topics = 0
                if user_id:
                    total_topics_result = conn.execute(
                        'SELECT COUNT(DISTINCT topic) as count FROM qbank WHERE LOWER(subject) = ?',
                        (subject.lower(),)
                    ).fetchone()
                    total_topics = total_topics_result['count'] if total_topics_result else 0
                    
                    completed_topics_result = conn.execute(
                        'SELECT COUNT(*) as count FROM topic_completion WHERE user_id = ? AND LOWER(subject) = ?',
                        (user_id, subject.lower())
                    ).fetchone()
                    completed_topics = completed_topics_result['count'] if completed_topics_result else 0
                
                matched_subjects.append({
                    'name': subject,
                    'completed_topics': completed_topics,
                    'total_topics': total_topics
                })
        
        if matched_subjects:
            grouped_subjects[year] = matched_subjects

    conn.close()

    # Fallback: if nothing matched, just show all subjects
    if not grouped_subjects:
        grouped_subjects["Available Subjects"] = [{'name': s.title(), 'completed_topics': 0, 'total_topics': 0} for s in db_subjects]

    return render_template('home.html', grouped_subjects=grouped_subjects)

@app.route('/subject/<subject_name>')
def show_subject(subject_name):
    """Subject page - Accessible to everyone"""
    conn = get_db_connection()
    user_id = session.get('user_id')

    # Get all chapters for this subject
    chapters = conn.execute(
        '''
        SELECT DISTINCT chapter 
        FROM qbank 
        WHERE LOWER(subject) = ? AND chapter != "" 
        ORDER BY chapter
        ''',
        (subject_name.lower(),)
    ).fetchall()

    # For each chapter, get the topics with question counts
    chapters_with_topics = []
    for row in chapters:
        chapter = row['chapter']
        topics = conn.execute(
            '''
            SELECT DISTINCT topic 
            FROM qbank 
            WHERE LOWER(subject) = ? AND chapter = ? AND topic != "" 
            ORDER BY topic
            ''',
            (subject_name.lower(), chapter)
        ).fetchall()
        
        # Enhanced topic list with question counts and access information
        enhanced_topics = []
        for topic_row in topics:
            topic_name = topic_row['topic']
            question_count = get_question_count(conn, subject_name, topic_name)
            is_completed = is_topic_completed(conn, user_id, subject_name, topic_name)
            
            # Check if topic requires login (FIXED: Only show lock if user is NOT logged in)
            topic_requires_login = is_topic_login_required(subject_name, topic_name)
            show_lock = topic_requires_login and not user_id  # Only show lock if login required AND user not logged in
            
            # Generate a rating based on question count
            if question_count >= 50:
                rating = 4.8
            elif question_count >= 30:
                rating = 4.5
            elif question_count >= 15:
                rating = 4.2
            elif question_count >= 5:
                rating = 4.0
            else:
                rating = 3.8
            
            # Determine status - show login required only if user not logged in
            if show_lock:
                status = 'LOGIN REQUIRED'
            else:
                status = 'FREE'
            
            topic_data = {
                'name': topic_name,
                'question_count': question_count,
                'rating': rating,
                'status': status,
                'completed': is_completed,
                'requires_login': show_lock  # This controls the lock icon
            }
            enhanced_topics.append(topic_data)
        
        chapters_with_topics.append({
            'chapter': chapter, 
            'topics': enhanced_topics
        })

    conn.close()
    return render_template('subject_chapters.html',
                           subject=subject_name.title(),
                           chapters=chapters_with_topics)

@app.route('/subject/<subject_name>/topic/<topic_name>')
def show_topic(subject_name, topic_name):
    """Topic route - CORRECTED: Most topics require login, only specific ones are free"""
    
    # Check if this specific topic requires login (CORRECTED LOGIC)
    if is_topic_login_required(subject_name, topic_name):
        user_id = ensure_user_session()
        if not user_id:
            flash('🔒 This topic requires login to access. Please sign up or log in to continue your medical studies.', 'info')
            return redirect(url_for('signup', restricted=True))
    
    # Topic is accessible - proceed to show content
    conn = get_db_connection()
    row = conn.execute(
        'SELECT id FROM qbank WHERE LOWER(subject)=? AND topic=? ORDER BY id LIMIT 1',
        (subject_name.lower(), topic_name)
    ).fetchone()
    conn.close()

    if row:
        return redirect(url_for(
            'show_question',
            subject_name=subject_name,
            topic_name=topic_name,
            qid=row['id']
        ))
    return "<h2>No questions found for this topic</h2>"

@app.route('/subject/<subject_name>/topic/<topic_name>/question/<int:qid>')
def show_question(subject_name, topic_name, qid):
    """Question route - Check access for login-required topics"""
    
    # Check if this topic requires login
    if is_topic_login_required(subject_name, topic_name):
        user_id = ensure_user_session()
        if not user_id:
            flash('🔒 This content requires login. Please sign up or log in to continue.', 'info')
            return redirect(url_for('signup', restricted=True))
    
    conn = get_db_connection()
    user_id = session.get('user_id')

    # Get all question ids for pagination
    all_ids = conn.execute(
        'SELECT id FROM qbank WHERE LOWER(subject)=? AND topic=? ORDER BY id',
        (subject_name.lower(), topic_name)
    ).fetchall()
    id_list = [r['id'] for r in all_ids]

    try:
        index = id_list.index(qid)
    except ValueError:
        conn.close()
        return "<h2>Question not found</h2>"

    prev_qid = id_list[index-1] if index > 0 else None
    next_qid = id_list[index+1] if index < len(id_list)-1 else None
    is_last_question = index == len(id_list) - 1

    question = conn.execute('SELECT * FROM qbank WHERE id=?', (qid,)).fetchone()
    bookmarked = is_bookmarked(conn, user_id, qid)
    
    # Get next topic for navigation
    next_topic = get_next_topic(conn, subject_name, topic_name) if is_last_question else None
    
    conn.close()

    return render_template(
        'question.html',
        subject=subject_name,
        topic=topic_name,
        q=question,
        current_index=index + 1,
        total=len(id_list),
        prev_qid=prev_qid,
        next_qid=next_qid,
        is_last_question=is_last_question,
        next_topic=next_topic,
        bookmarked=bookmarked
    )

@app.route('/subject/<subject_name>/topic/<topic_name>/answer/<int:qid>')
def show_answer(subject_name, topic_name, qid):
    """Answer route - Check access for login-required topics"""
    
    # Check if this topic requires login
    if is_topic_login_required(subject_name, topic_name):
        user_id = ensure_user_session()
        if not user_id:
            flash('🔒 This content requires login. Please sign up or log in to access detailed answers.', 'info')
            return redirect(url_for('signup', restricted=True))
    
    conn = get_db_connection()
    user_id = session.get('user_id')
    
    all_ids = conn.execute(
        'SELECT id FROM qbank WHERE LOWER(subject)=? AND topic=? ORDER BY id',
        (subject_name.lower(), topic_name)
    ).fetchall()
    id_list = [r['id'] for r in all_ids]

    try:
        index = id_list.index(qid)
    except ValueError:
        conn.close()
        return "<h2>Answer not found</h2>"

    prev_qid = id_list[index-1] if index > 0 else None
    next_qid = id_list[index+1] if index < len(id_list)-1 else None
    is_last_question = index == len(id_list) - 1

    q = conn.execute('SELECT * FROM qbank WHERE id=?', (qid,)).fetchone()
    bookmarked = is_bookmarked(conn, user_id, qid)
    user_note = get_user_note(conn, user_id, qid)
    
    # Get next topic for navigation
    next_topic = get_next_topic(conn, subject_name, topic_name) if is_last_question else None
    
    conn.close()

    return render_template(
        'answer.html',
        subject=subject_name,
        topic=topic_name,
        q=q,
        current_index=index + 1,
        total=len(id_list),
        prev_qid=prev_qid,
        next_qid=next_qid,
        is_last_question=is_last_question,
        next_topic=next_topic,
        bookmarked=bookmarked,
        user_note=user_note
    )

if __name__ == '__main__':
    app.run(debug=True)
