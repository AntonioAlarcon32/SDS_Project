import mongomock
from fastapi import FastAPI
import uvicorn




class Database:

    mongoClient: mongomock.MongoClient
    collection: mongomock.Collection
    field: str = "stringField"

    def __init__(self):
        self.mongoClient = mongomock.MongoClient()
        db = self.mongoClient['db']
        self.collection = db['onlyCollection']
        self.collection.insert_one({self.field: 'StringLocatedInDatabase'})
    
    def getString(self) -> str:
        return self.collection.find_one()[self.field]


class Api:

    app: FastAPI
    database: Database

    def __init__(self):
        self.database = Database()
        self.app = FastAPI()
        self.add_routes()
    
    def add_routes(self):
        @self.app.get("/hardcoded-string")
        async def getHardcodedString():
            return "AHarcodedString"
        
        @self.app.get("/database-string")
        async def getStringFromDatabase():
            return self.database.getString()

    def start(self, host: str, port: int):
        uvicorn.run(self.app, host=host, port=port)



if __name__ == "__main__":
    api: Api = Api()
    api.start("0.0.0.0", 80)