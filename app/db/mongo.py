from pymongo import MongoClient
from app.config import settings

client = MongoClient(
    settings.mongodb_url, 
    serverSelectionTimeoutMS=2000, 
    connectTimeoutMS=2000
)
db = client[settings.database_name]
collection = db["url_scans"]
