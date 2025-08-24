# requirements.txt (install these manually: pip install fastapi uvicorn sqlalchemy pydantic python-jose[cryptography] passlib[bcrypt] databases[sqlite])

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy import create_engine, Column, Integer, String, Text, ForeignKey, DateTime, Enum as SQLEnum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from databases import Database
import enum
import os

# Configuration
SECRET_KEY = "your_secret_key"  # Change this in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DATABASE_URL = "sqlite:///./lcms.db"

# Database setup
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
database = Database(DATABASE_URL)

# Enums
class Role(enum.Enum):
    admin = "admin"
    instructor = "instructor"
    student = "student"

class ProgressStatus(enum.Enum):
    not_started = "not_started"
    in_progress = "in_progress"
    completed = "completed"

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    role = Column(SQLEnum(Role))
    courses = relationship("Course", back_populates="instructor")
    enrollments = relationship("Enrollment", back_populates="student")
    progresses = relationship("Progress", back_populates="student")

class Course(Base):
    __tablename__ = "courses"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(Text)
    instructor_id = Column(Integer, ForeignKey("users.id"))
    instructor = relationship("User", back_populates="courses")
    modules = relationship("Module", back_populates="course")
    enrollments = relationship("Enrollment", back_populates="course")

class Enrollment(Base):
    __tablename__ = "enrollments"
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"))
    course_id = Column(Integer, ForeignKey("courses.id"))
    enrolled_at = Column(DateTime, default=datetime.utcnow)
    student = relationship("User", back_populates="enrollments")
    course = relationship("Course", back_populates="enrollments")

class Module(Base):
    __tablename__ = "modules"
    id = Column(Integer, primary_key=True, index=True)
    course_id = Column(Integer, ForeignKey("courses.id"))
    title = Column(String)
    order = Column(Integer)
    course = relationship("Course", back_populates="modules")
    lessons = relationship("Lesson", back_populates="module")

class Lesson(Base):
    __tablename__ = "lessons"
    id = Column(Integer, primary_key=True, index=True)
    module_id = Column(Integer, ForeignKey("modules.id"))
    title = Column(String)
    content = Column(Text)
    order = Column(Integer)
    module = relationship("Module", back_populates="lessons")
    quizzes = relationship("Quiz", back_populates="lesson")
    progresses = relationship("Progress", back_populates="lesson")

class Quiz(Base):
    __tablename__ = "quizzes"
    id = Column(Integer, primary_key=True, index=True)
    lesson_id = Column(Integer, ForeignKey("lessons.id"))
    title = Column(String)
    questions = Column(Text)  # JSON string for questions
    lesson = relationship("Lesson", back_populates="quizzes")

class Progress(Base):
    __tablename__ = "progresses"
    id = Column(Integer, primary_key=True, index=True)
    student_id = Column(Integer, ForeignKey("users.id"))
    lesson_id = Column(Integer, ForeignKey("lessons.id"))
    status = Column(SQLEnum(ProgressStatus), default=ProgressStatus.not_started)
    score = Column(Integer, nullable=True)  # For quizzes
    updated_at = Column(DateTime, default=datetime.utcnow)
    student = relationship("User", back_populates="progresses")
    lesson = relationship("Lesson", back_populates="progresses")

# Create tables
Base.metadata.create_all(bind=engine)

# Pydantic Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None

class UserBase(BaseModel):
    username: str
    email: str
    role: Role

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True

class CourseBase(BaseModel):
    title: str
    description: str

class CourseCreate(CourseBase):
    pass

class CourseResponse(CourseBase):
    id: int
    instructor_id: int

    class Config:
        from_attributes = True

class EnrollmentBase(BaseModel):
    course_id: int

class EnrollmentResponse(BaseModel):
    id: int
    student_id: int
    course_id: int
    enrolled_at: datetime

    class Config:
        from_attributes = True

class ModuleBase(BaseModel):
    title: str
    order: int

class ModuleCreate(ModuleBase):
    course_id: int

class ModuleResponse(ModuleBase):
    id: int
    course_id: int

    class Config:
        from_attributes = True

class LessonBase(BaseModel):
    title: str
    content: str
    order: int

class LessonCreate(LessonBase):
    module_id: int

class LessonResponse(LessonBase):
    id: int
    module_id: int

    class Config:
        from_attributes = True

class QuizBase(BaseModel):
    title: str
    questions: str  # JSON string

class QuizCreate(QuizBase):
    lesson_id: int

class QuizResponse(QuizBase):
    id: int
    lesson_id: int

    class Config:
        from_attributes = True

class ProgressBase(BaseModel):
    status: ProgressStatus
    score: int | None = None

class ProgressUpdate(ProgressBase):
    pass

class ProgressResponse(ProgressBase):
    id: int
    student_id: int
    lesson_id: int
    updated_at: datetime

    class Config:
        from_attributes = True

# Auth utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db=Depends()):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# Dependency for DB session
async def get_db():
    async with database:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

# CRUD operations
async def get_user_by_username(db, username: str):
    return db.query(User).filter(User.username == username).first()

async def get_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()

async def create_user(db, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(username=user.username, email=user.email, hashed_password=hashed_password, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

async def authenticate_user(db, username: str, password: str):
    user = await get_user_by_username(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Similar CRUD for other models...

# For brevity, I'll implement key ones. You can extend similarly.

async def create_course(db, course: CourseCreate, instructor_id: int):
    db_course = Course(**course.dict(), instructor_id=instructor_id)
    db.add(db_course)
    db.commit()
    db.refresh(db_course)
    return db_course

async def get_courses(db, skip: int = 0, limit: int = 100):
    return db.query(Course).offset(skip).limit(limit).all()

async def enroll_student(db, student_id: int, course_id: int):
    db_enrollment = Enrollment(student_id=student_id, course_id=course_id)
    db.add(db_enrollment)
    db.commit()
    db.refresh(db_enrollment)
    return db_enrollment

async def create_module(db, module: ModuleCreate):
    db_module = Module(**module.dict())
    db.add(db_module)
    db.commit()
    db.refresh(db_module)
    return db_module

async def create_lesson(db, lesson: LessonCreate):
    db_lesson = Lesson(**lesson.dict())
    db.add(db_lesson)
    db.commit()
    db.refresh(db_lesson)
    return db_lesson

async def create_quiz(db, quiz: QuizCreate):
    db_quiz = Quiz(**quiz.dict())
    db.add(db_quiz)
    db.commit()
    db.refresh(db_quiz)
    return db_quiz

async def update_progress(db, student_id: int, lesson_id: int, progress: ProgressUpdate):
    db_progress = db.query(Progress).filter(Progress.student_id == student_id, Progress.lesson_id == lesson_id).first()
    if not db_progress:
        db_progress = Progress(student_id=student_id, lesson_id=lesson_id, **progress.dict())
        db.add(db_progress)
    else:
        for key, value in progress.dict().items():
            setattr(db_progress, key, value)
        db_progress.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_progress)
    return db_progress

async def get_progress(db, student_id: int, lesson_id: int):
    return db.query(Progress).filter(Progress.student_id == student_id, Progress.lesson_id == lesson_id).first()

# FastAPI app
app = FastAPI(title="LCMS Backend")

# Routes
@app.post("/users/", response_model=UserResponse)
async def create_user_route(user: UserCreate, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != Role.admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    db_user = await get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return await create_user(db, user)

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)):
    user = await authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

@app.post("/courses/", response_model=CourseResponse)
async def create_course_route(course: CourseCreate, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role not in [Role.admin, Role.instructor]:
        raise HTTPException(status_code=403, detail="Instructor or admin access required")
    return await create_course(db, course, current_user.id)

@app.get("/courses/", response_model=list[CourseResponse])
async def get_courses_route(db=Depends(get_db)):
    return await get_courses(db)

@app.post("/enroll/", response_model=EnrollmentResponse)
async def enroll_route(enrollment: EnrollmentBase, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != Role.student:
        raise HTTPException(status_code=403, detail="Student access required")
    return await enroll_student(db, current_user.id, enrollment.course_id)

@app.post("/modules/", response_model=ModuleResponse)
async def create_module_route(module: ModuleCreate, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    # Check if current_user is instructor of the course
    course = db.query(Course).filter(Course.id == module.course_id).first()
    if not course or course.instructor_id != current_user.id:
        raise HTTPException(status_code=403, detail="Instructor access to own course required")
    return await create_module(db, module)

@app.post("/lessons/", response_model=LessonResponse)
async def create_lesson_route(lesson: LessonCreate, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    # Similar check for module's course instructor
    module = db.query(Module).filter(Module.id == lesson.module_id).first()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    course = db.query(Course).filter(Course.id == module.course_id).first()
    if course.instructor_id != current_user.id:
        raise HTTPException(status_code=403, detail="Instructor access required")
    return await create_lesson(db, lesson)

@app.post("/quizzes/", response_model=QuizResponse)
async def create_quiz_route(quiz: QuizCreate, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    # Similar check
    lesson = db.query(Lesson).filter(Lesson.id == quiz.lesson_id).first()
    if not lesson:
        raise HTTPException(status_code=404, detail="Lesson not found")
    module = db.query(Module).filter(Module.id == lesson.module_id).first()
    course = db.query(Course).filter(Course.id == module.course_id).first()
    if course.instructor_id != current_user.id:
        raise HTTPException(status_code=403, detail="Instructor access required")
    return await create_quiz(db, quiz)

@app.put("/progress/{lesson_id}", response_model=ProgressResponse)
async def update_progress_route(lesson_id: int, progress: ProgressUpdate, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != Role.student:
        raise HTTPException(status_code=403, detail="Student access required")
    # Check if enrolled
    enrollment = db.query(Enrollment).join(Course).join(Module).join(Lesson).filter(Enrollment.student_id == current_user.id, Lesson.id == lesson_id).first()
    if not enrollment:
        raise HTTPException(status_code=403, detail="Not enrolled in this course")
    return await update_progress(db, current_user.id, lesson_id, progress)

@app.get("/progress/{lesson_id}", response_model=ProgressResponse)
async def get_progress_route(lesson_id: int, db=Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != Role.student:
        raise HTTPException(status_code=403, detail="Student access required")
    prog = await get_progress(db, current_user.id, lesson_id)
    if not prog:
        raise HTTPException(status_code=404, detail="Progress not found")
    return prog

# Run the app: uvicorn main:app --reload
# Note: This is a basic implementation. For production, add more security, error handling, pagination, etc.
# Quizzes questions are stored as JSON string; you can expand to separate models if needed.
# Admin can manage users, instructors create content, students enroll and track progress.
