# main.py (FastAPI Backend - No Admin Functionality & Login Error Fixed)
# Ensure bcrypt is installed: pip install bcrypt

from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext 
from pydantic import BaseModel, EmailStr, Field, ConfigDict 
from typing import List, Optional, Any, Dict
from datetime import datetime, timedelta
import motor.motor_asyncio 
import os
from bson import ObjectId
from dotenv import load_dotenv 
# Removed: from enum import Enum (UserRole is removed)

load_dotenv() 

USER_PROVIDED_ATLAS_STRING = "mongodb+srv://amysantiago779:j82T8isbalI7X63g@ethical.rm9ry9j.mongodb.net/?retryWrites=true&w=majority&appName=Ethical"
MONGO_DETAILS = os.getenv("MONGO_DETAILS")
if MONGO_DETAILS:
    print("Loaded MONGO_DETAILS from environment.")
else:
    if "<db_password>" in USER_PROVIDED_ATLAS_STRING:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!! WARNING: MONGO_DETAILS using default string with <db_password> placeholder. !!")
        MONGO_DETAILS = "mongodb://localhost:27017" 
        print(f"Falling back to MONGO_DETAILS: {MONGO_DETAILS}")
    else:
        MONGO_DETAILS = USER_PROVIDED_ATLAS_STRING
        print(f"Using provided ATLAS string for MONGO_DETAILS: {MONGO_DETAILS[:70]}...")


DATABASE_NAME = os.getenv("DATABASE_NAME", "Ethical")
# Removed: ADMIN_EMAIL

DEFAULT_SECRET_KEY = "your_strong_secret_key_here_replace_this_NOW_or_set_in_env"
SECRET_KEY = os.getenv("SECRET_KEY", DEFAULT_SECRET_KEY)
if SECRET_KEY == DEFAULT_SECRET_KEY and not os.getenv("SECRET_KEY"):
     print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
     print("!! WARNING: Using default SECRET_KEY. Set a strong key in .env for production. !!")
     print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")


ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 

try:
    client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_DETAILS, serverSelectionTimeoutMS=10000) 
    database = client[DATABASE_NAME]
    user_collection = database.get_collection("users")
    level_collection = database.get_collection("levels")
    leaderboard_collection = database.get_collection("leaderboard")
    user_level_attempts_collection = database.get_collection("user_level_attempts")
    print(f"Attempting to connect to MongoDB specified by MONGO_DETAILS...")
except Exception as e:
    print(f"!!!!!!!!!! FAILED TO INITIALIZE MONGODB CLIENT !!!!!!!!!!! Error: {e}")
    exit() 


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/users/token") 

# Removed: UserRole Enum

# --- Pydantic Models ---
class UserBase(BaseModel):
    email: EmailStr
    first_name: str = Field(..., min_length=1)
    last_name: str = Field(..., min_length=1)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8) 

class UserInDBBase(UserBase):
    id: str = Field(..., alias="_id") 
    points: int = 0
    completed_levels: List[str] = [] 
    hashed_password: str
    # Removed: role: UserRole = UserRole.STUDENT

    model_config = ConfigDict( 
        from_attributes=True, 
        populate_by_name=True, 
        # Removed: use_enum_values=True, (no enum to handle)
        json_encoders={datetime: lambda dt: dt.isoformat(), ObjectId: str}
    )

class UserPublic(UserBase): 
    id: str 
    points: int
    completed_levels: List[str]
    # Removed: role: UserRole
    model_config = ConfigDict(from_attributes=True) # Removed use_enum_values

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None
    # Removed: role: Optional[UserRole] = None 

class LevelBaseModel(BaseModel): 
    id: str 
    name: str
    difficulty: str 
    description: Optional[str] = None
    points_value: int
    video_url: Optional[str] = None
    video_description: Optional[str] = None
    instructions: Optional[str] = None 
    type: str 
    hint: Optional[str] = None 
    image_url: Optional[str] = None 
    valid_passwords: Optional[List[str]] = None 
    answer: Optional[Any] = None 
    flag: Optional[str] = None 

class LevelPublic(LevelBaseModel):
    failed_attempts: Optional[int] = None 
    model_config = ConfigDict(from_attributes=True)

class LevelInDB(LevelBaseModel):
    mongo_id: Optional[str] = Field(None, alias="_id") 
    model_config = ConfigDict( 
        from_attributes=True, populate_by_name=True, 
        json_encoders={ObjectId: str}
    )

class ChallengeSubmission(BaseModel):
    submission: Any 
    mode: str 
    time_taken: Optional[int] = None 

class LeaderboardEntry(BaseModel):
    user_id: str; user_name: str; level_id: str; time_taken: int 
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    model_config = ConfigDict(json_encoders={ObjectId: str}) 

class UserLevelAttempt(BaseModel):
    user_id: str; level_id: str
    failed_attempts: int = 0

app = FastAPI(title="Hackverse API")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True, 
    allow_methods=["*"], allow_headers=["*"],
)

def verify_password(plain_password, hashed_password): return pwd_context.verify(plain_password, hashed_password)
def get_password_hash(password): return pwd_context.hash(password)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_user_by_email(email: str) -> Optional[UserInDBBase]:
    user_doc = await user_collection.find_one({"email": email})
    if user_doc:
        if isinstance(user_doc.get("_id"), ObjectId): user_doc["_id"] = str(user_doc["_id"])
        # Removed role handling as role field is removed
        return UserInDBBase.model_validate(user_doc) 
    return None

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDBBase:
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError: raise credentials_exception
    user = await get_user_by_email(email=email)
    if user is None: raise credentials_exception
    return user

# Removed: get_current_admin_user dependency

@app.post("/api/users/signup", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def signup_user(user_data: UserCreate):
    if await user_collection.find_one({"email": user_data.email}):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    
    user_doc_to_insert = {
        "email": user_data.email, "first_name": user_data.first_name, "last_name": user_data.last_name,
        "hashed_password": get_password_hash(user_data.password), "points": 0, "completed_levels": []
        # Removed role assignment
    }
    try:
        result = await user_collection.insert_one(user_doc_to_insert)
        created_user_doc = await user_collection.find_one({"_id": result.inserted_id})
        if created_user_doc:
            return UserPublic( # Construct UserPublic without role
                id=str(created_user_doc["_id"]), email=created_user_doc["email"],
                first_name=created_user_doc["first_name"], last_name=created_user_doc["last_name"],
                points=created_user_doc["points"], completed_levels=created_user_doc["completed_levels"]
            )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User created but could not be retrieved.")
    except Exception as e:
        print(f"Error during user insertion or retrieval: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"An internal error occurred: {str(e)}")

@app.post("/api/users/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await get_user_by_email(email=form_data.username) 
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password", headers={"WWW-Authenticate": "Bearer"})
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Removed role from token data
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", response_model=UserPublic)
async def read_users_me(current_user: UserInDBBase = Depends(get_current_user)):
    # Construct UserPublic without role
    return UserPublic(
        id=current_user.id, email=current_user.email,
        first_name=current_user.first_name, last_name=current_user.last_name,
        points=current_user.points, completed_levels=current_user.completed_levels
    )

@app.get("/api/levels", response_model=List[LevelPublic])
async def get_all_levels(current_user: UserInDBBase = Depends(get_current_user)): # current_user dependency kept for consistency, can be removed if not strictly needed for this endpoint
    levels_cursor = level_collection.find({})
    return [LevelPublic.model_validate(level_doc) async for level_doc in levels_cursor]

@app.get("/api/levels/{level_str_id}", response_model=LevelPublic)
async def get_level_details(level_str_id: str, current_user: UserInDBBase = Depends(get_current_user)):
    level_doc = await level_collection.find_one({"id": level_str_id}) 
    if not level_doc: raise HTTPException(status_code=404, detail="Level not found")
    
    response_data = dict(level_doc) 
    if response_data.get("type") == "brute-force":
        attempt_doc = await user_level_attempts_collection.find_one(
            {"user_id": current_user.id, "level_id": level_str_id}
        )
        response_data["failed_attempts"] = attempt_doc["failed_attempts"] if attempt_doc else 0
    
    return LevelPublic.model_validate(response_data)

@app.post("/api/levels/{level_str_id}/hint", response_model=Dict[str, str]) 
async def get_level_hint(level_str_id: str, current_user: UserInDBBase = Depends(get_current_user)):
    level_doc_db = await level_collection.find_one({"id": level_str_id})
    if not level_doc_db: raise HTTPException(status_code=404, detail="Level not found")
    
    level_doc_for_model = dict(level_doc_db)
    if isinstance(level_doc_for_model.get("_id"), ObjectId):
        level_doc_for_model["_id"] = str(level_doc_for_model["_id"]) 
    level = LevelInDB.model_validate(level_doc_for_model) 
    
    if level.type == "brute-force":
        attempt_doc = await user_level_attempts_collection.find_one(
            {"user_id": current_user.id, "level_id": level_str_id}
        )
        failed_attempts = attempt_doc["failed_attempts"] if attempt_doc else 0
        if failed_attempts >= 5 and level.valid_passwords:
            return {"hint_text": f"Incorrect. Hint Unlocked: The password is one of: {', '.join(level.valid_passwords)}."}
        elif level.hint: 
             return {"hint_text": level.hint}
        else:
            return {"hint_text": f"Keep trying! Password list hint unlocks after 5 failed attempts. (Attempts: {failed_attempts})"}

    if not level.hint: raise HTTPException(status_code=404, detail="No hint available for this level.")
    return {"hint_text": level.hint}

@app.post("/api/levels/{level_str_id}/submit")
async def submit_level_attempt(
    level_str_id: str, 
    submission_data: ChallengeSubmission,
    current_user: UserInDBBase = Depends(get_current_user)
):
    level_doc_db = await level_collection.find_one({"id": level_str_id})           
    if not level_doc_db: raise HTTPException(status_code=404, detail="Level not found")

    level_doc_for_model = dict(level_doc_db)
    if isinstance(level_doc_for_model.get("_id"), ObjectId):
        level_doc_for_model["_id"] = str(level_doc_for_model["_id"])
    level = LevelInDB.model_validate(level_doc_for_model)

    is_correct = False
    message = "Incorrect submission. Try again."

    if level.type == "brute-force":
        submitted_username = submission_data.submission.get("username")
        submitted_password = submission_data.submission.get("password")
        correct_username = level.answer.get("username") if isinstance(level.answer, dict) else None
        
        if submitted_username == correct_username and submitted_password in (level.valid_passwords or []):
            is_correct = True
        else:
            update_result = await user_level_attempts_collection.update_one(
                {"user_id": current_user.id, "level_id": level_str_id},
                {"$inc": {"failed_attempts": 1}},
                upsert=True 
            )
            attempt_doc = await user_level_attempts_collection.find_one(
                 {"user_id": current_user.id, "level_id": level_str_id}
            )
            failed_attempts = attempt_doc["failed_attempts"] if attempt_doc else 1
            if failed_attempts >= 5 and level.valid_passwords:
                message = f"Incorrect. Hint Unlocked: The password is one of: {', '.join(level.valid_passwords)}."
            else:
                message = f"Incorrect. Try again. (Attempt {failed_attempts}/5 before password list hint)"
                
    elif level.type == "packet-sniffing":
        if isinstance(submission_data.submission, dict) and \
           isinstance(level.answer, dict) and \
           submission_data.submission.get("username") == level.answer.get("username") and \
           submission_data.submission.get("password") == level.answer.get("password"):
            is_correct = True
    elif level.type in ["steganography"]: 
        if isinstance(submission_data.submission, str) and submission_data.submission == level.flag:
            is_correct = True

    points_awarded = 0
    rank = None

    if is_correct:
        message = "Challenge completed successfully!"
        if level.id not in current_user.completed_levels: 
            points_awarded = level.points_value
            await user_collection.update_one(
                {"_id": ObjectId(current_user.id)}, 
                {"$inc": {"points": points_awarded}, "$addToSet": {"completed_levels": level.id}}
            )
        if level.type == "brute-force": 
            await user_level_attempts_collection.update_one(
                {"user_id": current_user.id, "level_id": level_str_id},
                {"$set": {"failed_attempts": 0}}, upsert=True
            )
        if submission_data.mode == "timed" and submission_data.time_taken is not None:
            entry = LeaderboardEntry(
                user_id=current_user.id, user_name=f"{current_user.first_name} {current_user.last_name}",
                level_id=level.id, time_taken=submission_data.time_taken
            )
            await leaderboard_collection.insert_one(entry.model_dump())
            faster_entries_count = await leaderboard_collection.count_documents(
                {"level_id": level.id, "time_taken": {"$lt": submission_data.time_taken}}
            )
            rank = faster_entries_count + 1
        return { "correct": True, "message": message, "points_awarded": points_awarded, "rank": rank }
    else:
        return {"correct": False, "message": message}

# Removed Admin Endpoints: /api/admin/users and /api/admin/users/{user_id_to_reset}/reset-progress

@app.get("/api/leaderboard/{level_str_id}", response_model=List[LeaderboardEntry])
async def get_leaderboard_for_level(level_str_id: str, current_user: UserInDBBase = Depends(get_current_user)):
    entries_cursor = leaderboard_collection.find({"level_id": level_str_id}).sort("time_taken", 1).limit(100) 
    return [LeaderboardEntry.model_validate(entry_doc) async for entry_doc in entries_cursor]

async def populate_dummy_levels():
    if await level_collection.count_documents({}) == 0:
        dummy_levels_data = [
            {
                "id": "brute-force-01", "name": "Login Portal Crack", "difficulty": "Easy", "points_value": 30,
                "type": "brute-force", "description": "A simple login form. The username is 'admin'. Try common passwords.",
                "video_url": "https://www.youtube.com/watch?v=_KZuBMBZdeU", 
                "video_description": "Learn about basic brute-force attacks.",
                "instructions": "The username for the login portal is 'admin'. Your task is to find a working password. Common, weak passwords are often the first target for attackers.",
                "answer": {"username": "admin"}, 
                "valid_passwords": ["password", "123456", "admin123", "qwerty", "user123", "letmein", "abc123", "welcome", "admin", "12345", "12345678", "iloveyou", "1234", "AdMiN@123"], 
                "hint": "Think of very simple, commonly used passwords. The password list will be revealed after 5 incorrect attempts." 
            },
            {
                "id": "steganography-01", "name": "Hidden Message", "difficulty": "Medium", "points_value": 50,
                "type": "steganography", "description": "Find the secret message hidden in the image.",
                "video_url": "https://www.youtube.com/watch?v=I9WwX3EHdyY", 
                "video_description": "Introduction to steganography techniques.",
                "image_url": "steganography_challenge_image.jpg", 
                "instructions": "The flag is in the format FLAG{...}. Download the image and use tools or techniques to find data hidden within it.",
                "flag": "FLAG{S3CR3T_IN_IMG}",
                "hint": "Common steganography involves hiding data in the least significant bits of image pixels, try using tools like Stegonline, keeping the R G B as 0 0 0."
            },
            {
                "id": "packet-sniffing-01", "name": "Hacker Café - Packet Sniffing", "difficulty": "Hard", "points_value": 75,
                "type": "packet-sniffing", 
                "description": "Sniff HTTP traffic at a café Wi-Fi to find login credentials.",
                "video_url": "YOUR_PACKET_SNIFFING_VIDEO_URL",
                "video_description": "Learn about packet sniffing and why HTTPS is important.",
                "instructions": "You're connected to an open Wi-Fi at a café. One of the users logs into a website using HTTP. Use the simulated 'MiniShark' tool to inspect the traffic, find their plain-text credentials (username and password), and submit them.",
                "answer": {"username": "HELXLO", "password": "CONGRATULATIONSX"}, 
                "hint": "Look for HTTP POST requests to login pages. Credentials are often sent as form data in the request body (e.g., username=someuser&password=somepass)."
            }
        ]
        await level_collection.insert_many(dummy_levels_data)
        print("Dummy levels populated.")

@app.on_event("startup")
async def startup_event():
    try:
        await client.admin.command('ping')
        print("Successfully connected to MongoDB!")
        await user_collection.create_index("email", unique=True)
        # Removed: await user_collection.create_index("role")
        await level_collection.create_index("id", unique=True) 
        await leaderboard_collection.create_index([("level_id", 1), ("time_taken", 1)])
        await user_level_attempts_collection.create_index([("user_id", 1), ("level_id", 1)], unique=True)
        print("Database indexes ensured.")
        await populate_dummy_levels() 
    except Exception as e:
        print(f"!!!!!!!!!! ERROR DURING STARTUP !!!!!!!!!!! Error: {e}")
    print("FastAPI application startup complete.")

# To run: uvicorn main:app --reload
