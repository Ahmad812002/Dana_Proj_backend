from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')


# mongodb+srv://ahmad812002_db_user:<db_password>@dana.51p0ug4.mongodb.net/

# MongoDB


import os

mongo_url = os.environ.get("MONGO_URL")
db_name = os.environ.get("DB_NAME")

client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

print("MONGO_URL:", mongo_url)
print("DB_NAME:", db_name)


# JWT + Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get("JWT_SECRET", "vperfumes-secret-key-2025")
ALGORITHM = "HS256"
security = HTTPBearer()

# FastAPI App
app = FastAPI()
api_router = APIRouter(prefix="/api")

@app.get("/api")
async def get_data():
    return {"message": "Hello from the backend!"}

    if __name__ == '__main__':
            # Get the port number from the environment variable set by Render
            port = int(os.environ.get('PORT', 5000))
            # Run the app, listening on all available network interfaces
            app.run(host='0.0.0.0', port=port)



print("Connecting to Mongo...")
try:
    client.admin.command("ping")
    print("MongoDB Connected!")
except Exception as e:
    print("MongoDB Error:", e)



class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    role: str  # "admin" or "company"
    company_name: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(BaseModel):
    username: str
    password: str
    role: str
    company_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class Order(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    order_number: str
    customer_name: str
    customer_phone: str
    delivery_area: str
    order_price: Optional[float] = 0.0  # Made optional for backward compatibility
    delivery_cost: float
    status: str  # "جاري" or "تم" or "ملغي"
    order_date: str
    notes: Optional[str] = None
    company_id: str
    company_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class OrderCreate(BaseModel):
    order_number: str
    customer_name: str
    customer_phone: str
    delivery_area: str
    order_price: Optional[float] = 0.0
    delivery_cost: float
    status: str
    order_date: str
    notes: Optional[str] = None

class OrderUpdate(BaseModel):
    order_number: Optional[str] = None
    customer_name: Optional[str] = None
    customer_phone: Optional[str] = None
    delivery_area: Optional[str] = None
    order_price: Optional[float] = None
    delivery_cost: Optional[float] = None
    status: Optional[str] = None
    order_date: Optional[str] = None
    notes: Optional[str] = None

class OrderHistory(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    order_id: str
    action: str  # "created" or "updated"
    changes: dict
    user_id: str
    username: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ============= Helper Functions =============

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# ============= Routes =============

@api_router.get("/")
async def root():
    return {"message": "VPerfumes Order Tracking API"}

# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate, current_user: dict = Depends(get_current_user)):
    # Only admin can create new users
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create users")
    
    # Check if username exists
    existing_user = await db.users.find_one({"username": user_data.username})
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    # Create user
    user = User(
        username=user_data.username,
        password_hash=hash_password(user_data.password),
        role=user_data.role,
        company_name=user_data.company_name
    )
    
    doc = user.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.users.insert_one(doc)
    
    return {"message": "User created successfully", "username": user.username}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"username": credentials.username}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_access_token({"sub": user["id"], "role": user["role"]})
    
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "company_name": user.get("company_name")
        }
    }

@api_router.post("/auth/change-password")
async def change_password(password_data: PasswordChange, current_user: dict = Depends(get_current_user)):
    # Verify current password
    user = await db.users.find_one({"id": current_user["id"]}, {"_id": 0})
    if not user or not verify_password(password_data.current_password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="كلمة المرور الحالية غير صحيحة")
    
    # Update password
    new_hash = hash_password(password_data.new_password)
    await db.users.update_one({"id": current_user["id"]}, {"$set": {"password_hash": new_hash}})
    
    return {"message": "تم تغيير كلمة المرور بنجاح"}

# Order Routes
@api_router.get("/orders", response_model=List[Order])
async def get_orders(current_user: dict = Depends(get_current_user)):
    query = {}
    
    # If company user, only show their orders
    if current_user["role"] == "company":
        query["company_id"] = current_user["id"]
    
    orders = await db.orders.find(query, {"_id": 0}).to_list(10000)
    
    # Convert ISO strings to datetime
    for order in orders:
        if isinstance(order['created_at'], str):
            order['created_at'] = datetime.fromisoformat(order['created_at'])
        if isinstance(order['updated_at'], str):
            order['updated_at'] = datetime.fromisoformat(order['updated_at'])
    
    # Sort by created_at descending
    orders.sort(key=lambda x: x['created_at'], reverse=True)
    
    return orders

@api_router.post("/orders", response_model=Order)
async def create_order(order_data: OrderCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "company":
        raise HTTPException(status_code=403, detail="Only companies can create orders")
    
    # Check if order number exists for this company
    existing = await db.orders.find_one({
        "order_number": order_data.order_number,
        "company_id": current_user["id"]
    })
    if existing:
        raise HTTPException(status_code=400, detail="رقم الطلب موجود مسبقاً")
    
    order = Order(
        **order_data.model_dump(),
        company_id=current_user["id"],
        company_name=current_user["company_name"]
    )
    
    doc = order.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    
    await db.orders.insert_one(doc)
    
    # Create history entry - clean doc for JSON serialization
    clean_doc = {k: v for k, v in doc.items() if k != '_id'}
    history = OrderHistory(
        order_id=order.id,
        action="created",
        changes=clean_doc,
        user_id=current_user["id"],
        username=current_user["username"]
    )
    
    history_doc = history.model_dump()
    history_doc['timestamp'] = history_doc['timestamp'].isoformat()
    await db.order_history.insert_one(history_doc)
    
    return order

@api_router.put("/orders/{order_id}", response_model=Order)
async def update_order(order_id: str, order_data: OrderUpdate, current_user: dict = Depends(get_current_user)):
    # Find order
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    # Check permission
    if current_user["role"] == "company" and order["company_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="ليس لديك صلاحية لتعديل هذا الطلب")
    
    # Track changes
    changes = {}
    update_data = order_data.model_dump(exclude_unset=True)
    
    for key, new_value in update_data.items():
        if key in order and order[key] != new_value:
            changes[key] = {"old": order[key], "new": new_value}
    
    if not changes:
        return Order(**order)
    
    # Update order
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.orders.update_one({"id": order_id}, {"$set": update_data})
    
    # Create history entry
    history = OrderHistory(
        order_id=order_id,
        action="updated",
        changes=changes,
        user_id=current_user["id"],
        username=current_user["username"]
    )
    
    history_doc = history.model_dump()
    history_doc['timestamp'] = history_doc['timestamp'].isoformat()
    await db.order_history.insert_one(history_doc)
    
    # Get updated order
    updated_order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if isinstance(updated_order['created_at'], str):
        updated_order['created_at'] = datetime.fromisoformat(updated_order['created_at'])
    if isinstance(updated_order['updated_at'], str):
        updated_order['updated_at'] = datetime.fromisoformat(updated_order['updated_at'])
    
    return Order(**updated_order)

@api_router.delete("/orders/{order_id}")
async def delete_order(order_id: str, current_user: dict = Depends(get_current_user)):
    order = await db.orders.find_one({"id": order_id}, {"_id": 0})
    if not order:
        raise HTTPException(status_code=404, detail="الطلب غير موجود")
    
    # Check permission
    if current_user["role"] == "company" and order["company_id"] != current_user["id"]:
        raise HTTPException(status_code=403, detail="ليس لديك صلاحية لحذف هذا الطلب")
    
    await db.orders.delete_one({"id": order_id})
    
    # Create history entry - clean order data for JSON serialization
    clean_order = {k: v for k, v in order.items() if k != '_id'}
    history = OrderHistory(
        order_id=order_id,
        action="deleted",
        changes={"order": clean_order},
        user_id=current_user["id"],
        username=current_user["username"]
    )
    
    history_doc = history.model_dump()
    history_doc['timestamp'] = history_doc['timestamp'].isoformat()
    await db.order_history.insert_one(history_doc)
    
    return {"message": "تم حذف الطلب بنجاح"}

@api_router.get("/orders/{order_id}/history", response_model=List[OrderHistory])
async def get_order_history(order_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    history = await db.order_history.find({"order_id": order_id}, {"_id": 0}).to_list(1000)
    
    # Convert ISO strings to datetime and ensure no ObjectId fields
    for entry in history:
        if isinstance(entry['timestamp'], str):
            entry['timestamp'] = datetime.fromisoformat(entry['timestamp'])
        # Remove any potential ObjectId fields that might have slipped through
        entry.pop('_id', None)
    
    history.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return history

@api_router.get("/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    query = {}
    if current_user["role"] == "company":
        query["company_id"] = current_user["id"]
    
    total = await db.orders.count_documents(query)
    ongoing = await db.orders.count_documents({**query, "status": "جاري"})
    completed = await db.orders.count_documents({**query, "status": "تم"})
    cancelled = await db.orders.count_documents({**query, "status": "ملغي"})
    
    return {
        "total": total,
        "ongoing": ongoing,
        "completed": completed,
        "cancelled": cancelled
    }

# Company Management Routes (Admin only)
@api_router.get("/companies")
async def get_companies(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    companies = await db.users.find({"role": "company"}, {"_id": 0, "password_hash": 0}).to_list(1000)
    
    # Convert ISO strings to datetime
    for company in companies:
        if isinstance(company.get('created_at'), str):
            company['created_at'] = datetime.fromisoformat(company['created_at'])
    
    return companies

@api_router.delete("/companies/{company_id}")
async def delete_company(company_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    # Find company
    company = await db.users.find_one({"id": company_id, "role": "company"})
    if not company:
        raise HTTPException(status_code=404, detail="الشركة غير موجودة")
    
    # Only delete company user account (keep orders for archive)
    await db.users.delete_one({"id": company_id})
    
    return {"message": f"تم حذف حساب شركة {company['company_name']} بنجاح. الطلبات محفوظة في الأرشيف"}

@api_router.post("/companies/{company_id}/reset-password")
async def reset_company_password(company_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    
    # Find company
    company = await db.users.find_one({"id": company_id, "role": "company"})
    if not company:
        raise HTTPException(status_code=404, detail="الشركة غير موجودة")
    
    # Generate new random password
    import secrets
    import string
    new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(10))
    
    # Update password
    new_hash = hash_password(new_password)
    await db.users.update_one({"id": company_id}, {"$set": {"password_hash": new_hash}})
    
    return {
        "message": f"تم إعادة تعيين كلمة المرور لشركة {company['company_name']}",
        "company_name": company['company_name'],
        "username": company['username'],
        "new_password": new_password
    }

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

# Create default admin on startup
@app.on_event("startup")
async def create_default_admin():
    admin_exists = await db.users.find_one({"role": "admin"})
    if not admin_exists:
        admin_password = "admin123"  # any simple admin password
        admin = User(
            username="admin",
            password_hash=hash_password(admin_password),
            role="admin",
            company_name=None
        )
        doc = admin.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        await db.users.insert_one(doc)
        logger.info("Default admin created: username=admin, password=admin123")

