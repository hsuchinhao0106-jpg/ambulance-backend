from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional, List
from pydantic import BaseModel
import os, json

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./ambulance.db")
SECRET_KEY = os.environ.get("SECRET_KEY", "ambulance-secret-key-2024")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# DB setup
engine = create_engine(DATABASE_URL.replace("postgres://", "postgresql://") if DATABASE_URL.startswith("postgres://") else DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, default="staff")  # admin, staff, vehicle
    vehicle_id = Column(String, nullable=True)
    is_active = Column(Boolean, default=True)

class Record(Base):
    __tablename__ = "records"
    id = Column(String, primary_key=True)
    data = Column(Text, nullable=False)  # JSON
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class VehicleState(Base):
    __tablename__ = "vehicle_states"
    vehicle_id = Column(String, primary_key=True)
    status = Column(String, default="offline")
    crew = Column(Text, default="{}")  # JSON
    updated_at = Column(DateTime, default=datetime.utcnow)

class EmergencyRecord(Base):
    __tablename__ = "emergency_records"
    id = Column(String, primary_key=True)
    data = Column(Text, nullable=False)  # JSON
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Auth
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    return jwt.encode({**data, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id: raise HTTPException(status_code=401)
        user = db.query(User).filter(User.id == user_id).first()
        if not user: raise HTTPException(status_code=401)
        return user
    except JWTError: raise HTTPException(status_code=401, detail="Token 無效")

# Pydantic schemas
class LoginResponse(BaseModel):
    token: str
    user: dict

class UserCreate(BaseModel):
    id: str
    name: str
    password: str
    role: str
    vehicle_id: Optional[str] = None

class RecordIn(BaseModel):
    id: str
    data: dict

class VehicleStateIn(BaseModel):
    status: Optional[str] = None
    crew: Optional[dict] = None

# App
app = FastAPI(title="保群救護車 API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# 初始化預設用戶
def init_default_users(db: Session):
    defaults = [
        {"id":"u001","name":"翁子澐","password":"1111","role":"staff","vehicle_id":None},
        {"id":"u002","name":"陳昀碒","password":"2222","role":"admin","vehicle_id":None},
        {"id":"u003","name":"許晉豪","password":"3333","role":"staff","vehicle_id":None},
        {"id":"v001","name":"CAM-7952","password":"7952","role":"vehicle","vehicle_id":"CAM-7952"},
        {"id":"v002","name":"BVM-9372","password":"9372","role":"vehicle","vehicle_id":"BVM-9372"},
        {"id":"v003","name":"BUK-3021","password":"3021","role":"vehicle","vehicle_id":"BUK-3021"},
    ]
    for u in defaults:
        if not db.query(User).filter(User.id == u["id"]).first():
            db.add(User(id=u["id"], name=u["name"], password_hash=get_password_hash(u["password"]), role=u["role"], vehicle_id=u["vehicle_id"]))
    db.commit()

@app.on_event("startup")
def startup():
    db = SessionLocal()
    init_default_users(db)
    db.close()

# ===== Auth =====
@app.post("/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.name == form.username).first()
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=400, detail="帳號或密碼錯誤")
    token = create_access_token({"sub": user.id})
    return {"token": token, "user": {"id": user.id, "name": user.name, "role": user.role, "vehicleId": user.vehicle_id}}

# ===== Users =====
@app.get("/users")
def get_users(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(status_code=403)
    users = db.query(User).all()
    return [{"id":u.id,"name":u.name,"role":u.role,"vehicleId":u.vehicle_id} for u in users]

@app.post("/users")
def create_user(data: UserCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(status_code=403)
    if db.query(User).filter(User.id == data.id).first(): raise HTTPException(status_code=400, detail="ID 已存在")
    user = User(id=data.id, name=data.name, password_hash=get_password_hash(data.password), role=data.role, vehicle_id=data.vehicle_id)
    db.add(user); db.commit()
    return {"success": True}

@app.put("/users/{user_id}")
def update_user(user_id: str, data: UserCreate, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(status_code=403)
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404)
    user.name = data.name; user.role = data.role; user.vehicle_id = data.vehicle_id
    if data.password: user.password_hash = get_password_hash(data.password)
    db.commit()
    return {"success": True}

@app.delete("/users/{user_id}")
def delete_user(user_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role != "admin": raise HTTPException(status_code=403)
    user = db.query(User).filter(User.id == user_id).first()
    if not user: raise HTTPException(status_code=404)
    db.delete(user); db.commit()
    return {"success": True}

# ===== Records =====
@app.get("/records")
def get_records(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    records = db.query(Record).all()
    return [json.loads(r.data) for r in records]

@app.post("/records")
def upsert_record(data: RecordIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(Record).filter(Record.id == data.id).first()
    if record:
        record.data = json.dumps(data.data, ensure_ascii=False); record.updated_at = datetime.utcnow()
    else:
        db.add(Record(id=data.id, data=json.dumps(data.data, ensure_ascii=False)))
    db.commit()
    return {"success": True}

@app.delete("/records/{record_id}")
def delete_record(record_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(Record).filter(Record.id == record_id).first()
    if record: db.delete(record); db.commit()
    return {"success": True}

# ===== Vehicle States =====
@app.get("/vehicle-states")
def get_vehicle_states(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    states = db.query(VehicleState).all()
    status_dict = {s.vehicle_id: s.status for s in states}
    crew_dict = {s.vehicle_id: json.loads(s.crew) for s in states}
    return {"vehicleStatus": status_dict, "vehicleCrew": crew_dict}

@app.put("/vehicle-states/{vehicle_id}")
def update_vehicle_state(vehicle_id: str, data: VehicleStateIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    state = db.query(VehicleState).filter(VehicleState.vehicle_id == vehicle_id).first()
    if not state:
        state = VehicleState(vehicle_id=vehicle_id)
        db.add(state)
    if data.status is not None: state.status = data.status
    if data.crew is not None: state.crew = json.dumps(data.crew, ensure_ascii=False)
    state.updated_at = datetime.utcnow()
    db.commit()
    return {"success": True}

# ===== Emergency Records =====
@app.get("/emergency-records")
def get_emergency_records(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    records = db.query(EmergencyRecord).all()
    return [json.loads(r.data) for r in records]

@app.post("/emergency-records")
def upsert_emergency_record(data: RecordIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(EmergencyRecord).filter(EmergencyRecord.id == data.id).first()
    if record:
        record.data = json.dumps(data.data, ensure_ascii=False)
    else:
        db.add(EmergencyRecord(id=data.id, data=json.dumps(data.data, ensure_ascii=False)))
    db.commit()
    return {"success": True}

@app.get("/health")
def health(): return {"status": "ok"}
