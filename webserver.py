from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn
import requests

class Webserver:

    app: FastAPI
    dbApiUrl: str

    def __init__(self):
        self.app = FastAPI()
        self.dbApiUrl = "http://10.0.3.2:80"
        self.add_routes()
    
    def add_routes(self):
        @self.app.get("/")
        async def getRoot():
            return "This is the root route"
        
        @self.app.get("/hello-world-json")
        async def getHelloWorld():
            return {"message": "Hello World"}
        
        @self.app.get("/string-from-database", response_class=HTMLResponse)
        async def getAnHtml():
            stringFromDatabase: str = requests.get(url = self.dbApiUrl + "/database-string").text
            return f"""
            <html>
                <head>
                    <title>Response from database</title>
                </head>
                <body>
                    <h1>{stringFromDatabase}</h1>
                </body>
            </html>
            """

    def start(self, host: str, port: int):
        uvicorn.run(self.app, host=host, port=port)

if __name__ == "__main__":
    server: Webserver = Webserver()
    server.start("0.0.0.0", 80)