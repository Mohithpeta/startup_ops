from pymongo import MongoClient


client = MongoClient("mongodb://localhost:27017/")
db = client["startup_ops"]
user_collection = db["users_collection"]
organization_collection = db["organizations_collection"]


