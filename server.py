from flask import *
from pymongo import *
from bson import *
import bcrypt
import jwt
import os


app = Flask(__name__)

client = MongoClient('localhost:27017')
db = client.Polling

def find_teacher_token(token):
    teacher = db.teachers.find_one({
        "tokens": {"$in": [token]}
    })
    email = teacher['email']
    teacher_email = email
    print(teacher_email)
    return teacher_email #teacher's email

def find_student_token(token):
    student = db.students.find_one({
        "tokens": {"$in": [token]}
    })
    email = student['email']
    student_email = email
    return student_email

def gen_token(email):
    rand = os.urandom(6)
    print(str(rand))
    jwt_token = jwt.encode({'some': email}, 'secret', algorithm='HS256')
    token = jwt_token.decode('utf-8')
    #print(type(token))
    #print(token)
    #print(str(token))
    #print(type([str(token)][0]))
    return token

def create_Student(email, password, name):
    db.students.create_index("email", unique=True)
    hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    token = gen_token(email)
    print(token)
    #print([str(token)])
    try:
        db.students.insert({"email": email,
               "password": hash,
               "name": name,
               "tokens": [token]})
    except:
        return None


def create_Student_Answers(email):
    db.answers.insert({
        "email": email,
        "archived": [],
        "current": None  # this will be removed when question is closed.
    })

"""Archived format, [
{
class: "class name",
answers: [a, b, c, d...],
score: 53,
total possible: 54
}


]"""

"""
Current format,

{
classroom: "cs 136",
answer: A

}

"""

def create_teacher(email, password, name):
    db.students.create_index("email", unique=True)
    hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    token = gen_token(email)
    db.teachers.insert({"email": email,
               "password": hash,
               "name": name,
               "tokens": [token]})

def create_scores(email):
    db.scores.insertOne({
        "email": email,
        "classes": {
            #name of class then score (session: score)
        }

    })

def login(email, password):
    user = db.students.find_one({"email": email})
    print(user)
    if(user == None):
        #No user found in students, check teachers
        teacher = db.teachers.find_one({"email": email})
        tokens = teacher['tokens']
        if bcrypt.checkpw(password.encode('utf-8'), teacher['password']):
            token = gen_token(email)
            tokens.append(token)
            #print(new_tokens)
            db.teachers.update_one({"email": email}, {'$set': {
                'tokens': tokens
            }})
            return token
        else:
            return "InvalidCred"
    else:
        #print(user['password'])
        tokens = user['tokens']
        print(tokens[0])
        if bcrypt.checkpw(password.encode('utf-8'), user['password']):
            token = gen_token(email)
            tokens.append(str(token))
            #print(new_tokens)
            db.students.update_one({"email": email}, {'$set': {
                'tokens': tokens
            }})
            return token
        else:
            return "InvalidCred"


def join_Session(email, classroom):
    session = db.sessions.find_one({"class": classroom})
    students = session['students']
    students.append(email)
    db.sessions.update_one({"class": classroom},{'$set': {
        'students': students
    }})

def create_Session(email, classroom):
    db.sessions.create_index("email", unique=True)
    db.sessions.insert({
        "email": email,
        "class": classroom,
        "students": [],
        "questions": [],
        "current question": {},
        "status": "on"
    })
    """ FORMAT:   { question: "",
                    options:  {A, B, C, D},
                    answer: E   }"""

def close_Session(classroom):
    db.sessions.update_one({"class": classroom, "status": "on"}, {'$set':{
        'status': 'off'
    }})

def broadcast_message(email): #teacher
    session = db.sessions.find_one({"email": email, "status": "on"})
    questions = session['questions']
    current = questions[0]
    print(questions)
    del questions[0]
    db.sessions.update_one({"email": email, "status": "on"}, {'$set':{
        "questions": questions,
        "current question": current

    }})


def receive_messages(email): #student side
    student_in_session = db.sessions.find_one({
        "status": "on",
        "students": {"$in": [email]}
    })
    question = student_in_session['current question']
    print(question)
    return question

def close_question(email):  #closes the current question, finalizing all answers.
    session = db.sessions.find_one({"email": email, "status": "on"})
    question = session['current question']
    db.sessions.update_one({"email": email, "status": "on"}, {'$set': {
        "current question": {}  #pulls out the current question (replaces with initial {})
    }})


def add_questions(email, classroom, questions):
   print(classroom + "  " + str(questions))
   db.sessions.update_one({ #questions added to session coming up.
       "email": email,
        "status": "on",
        "class": classroom
    }, {
        "$set": {
            "questions": questions
        }
    })


def answer_question(email, answer):
    session = db.sessions.find_one({"email": email, "status": "on"})
    student_profile = db.answers.find_one({"email": email})
    question = session['current-question']
    classroom = session['class']
    db.answers.update_one({"email": email}, {'$set': {
            "answer": answer
    }})



#login("emai","pas")
#create_student("emai", "pas", "garo")



@app.route('/')
def root():
    return "Root view reached"

@app.route('/create-account-student', methods=['POST'])
def create_student():
    body = request.get_json()
    email = body['email']
    password = body['password']
    name = body['name']
    create_Student(email, password, name)
    create_Student_Answers(email)
    return "Created"

@app.route('/login', methods=['POST'])
def login_route():
    body = request.get_json()
    email = body['email']
    password = body['password']
    token_new = login(email, password)
    print(token_new)
    resp = Response("Login Succeeded")
    resp.headers['x-auth'] = token_new
    return resp

@app.route('/create-session-teacher', methods=['POST'])
def create_session():
    body = request.get_json()
    classroom = body['classroom']
    header = request.headers.get('x-auth')
    print(header)
    teacher_email = find_teacher_token(header)
    print(teacher_email)
    create_Session(teacher_email, classroom)
    return "Session Created"

@app.route('/create-account-teacher', methods=['POST'])
def create_teach():
    body = request.get_json()
    email = body['email']
    password = body['password']
    name = body['name']
    create_teacher(email, password, name)
    return "Teacher created"

#request.headers.get('x-auth')

@app.route('/join-session') #url params (GET)
def join_session():
    body = request.args
    #passed in object ID
    classroom = body['id']
    header = request.headers.get('x-auth') #auth token
    email = find_student_token(header)
    join_Session(email, classroom)
    return "You've joined the session"


@app.route('/send-question', methods=['PATCH']) #within a session
def send_question():
    header = request.headers.get('x-auth')
    email = find_teacher_token(header)
    broadcast_message(email)
    return "Question has been broadcasted"


@app.route('/stop-question', methods=['PATCH'])
def stop_question():
    header = request.headers.get('x-auth')
    email = find_teacher_token(header)
    close_question(email)
    return "Question stopped, responses recorded."


@app.route('/add-questions', methods=['POST'])
def create_questions():
    body = request.get_json()
    classroom = body['classroom']
    questions = body['questions']
    header = request.headers.get('x-auth')
    print(header)
    email = find_teacher_token(header)
    add_questions(email, classroom, questions)
    return "questions added"


@app.route('/receive-question') #student (GET)
def receive():
    header = request.headers.get('x-auth')
    email = find_student_token(header)
    return receive_messages(email)

@app.route('/answer-question', methods=['POST'])
def answer():
    header = request.headers.get('x-auth')
    email = find_student_token(header)
    body = request.get_json()
    answer = body['answer']
    answer_question(email, answer)


@app.route('/close-session', methods=['POST'])
def close_session():
    header = request.headers.get('x-auth')
    classroom = request.get_json()['classroom']
    close_Session(classroom)
    return "Session finished"

if __name__ == "__main__":
    app.run()
