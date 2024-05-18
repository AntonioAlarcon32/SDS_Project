from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

class Webserver:

    app: FastAPI

    def __init__(self):
        self.app = FastAPI()
        self.add_routes()
    
    def add_routes(self):
        @self.app.get("/")
        async def getRoot():
            return "This is the root route"
        
        @self.app.get("/hello-world-json")
        async def getHelloWorld():
            return {"message": "Hello World"}
        
        @self.app.get("/hello-world-html", response_class=HTMLResponse)
        async def getAnHtml():
            return """
            <html>
                <head>
                    <title>Some HTML in here</title>
                </head>
                <body>
                    <h1>I'm tired, boss</h1>
                </body>
            </html>
            """

    def start(self, host: str, port: int):
        uvicorn.run(self.app, host=host, port=port)

if __name__ == "__main__":
    server: Webserver = Webserver()
    server.start("127.0.0.1", 80)