from motor.motor_asyncio import AsyncIOMotorClient

client = AsyncIOMotorClient("mongodb+srv://ahmad812002_db_user:Hamada.CS812002@dana.51p0ug4.mongodb.net/vperfumes")
db = client["vperfumes"]
print(db.list_collection_names())