import mongomock
from fastapi import FastAPI
import uvicorn




class Database:

    mongoClient: mongomock.MongoClient

    def __init__(self):
        self.mongoClient = mongomock.MongoClient()

    def initializeDatabase(self):
        db = self.mongoClient['db']
        collection = db['mycollection']
        collection.insert_one({'stringField': 'StringLocatedInDatabase'})
    
    def getString(self) -> str:
        db = self.mongoClient['db']
        collection = db['mycollection']
        return collection.find_one()


class Api:

    app: FastAPI
    database: Database

    def __init__(self):
        self.database = Database()
        self.app = FastAPI()
        self.add_routes()
    
    def add_routes(self):
        @self.app.get("/hardcodedString")
        async def getHardcodedString():
            return "AHarcodedString"
        
        @self.app.get("/databaseString")
        async def getHelloWorld():
            return self.database.getString()

    def start(self, host: str, port: int):
        uvicorn.run(self.app, host=host, port=port)



if __name__ == "__main__":
    api: Api = Api()
    api.start("0.0.0.0", 80)