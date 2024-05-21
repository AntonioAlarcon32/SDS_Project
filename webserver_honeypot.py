from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn

class HoneypotWebserver:

    app: FastAPI

    def __init__(self):
        self.app = FastAPI()
        self.add_routes()
    
    def add_routes(self):
        @self.app.get("/")
        async def getRoot():
            return "This is the root route of the honeypot"
        
        @self.app.get("/hello-world-json")
        async def getHelloWorld():
            return {"message": "Hello World from the honeypot"}
        
        @self.app.get("/string-from-database", response_class=HTMLResponse)
        async def getAnHtml():
            return """
            <html>
                <head>
                    <title>Response from webserver</title>
                </head>
                <body>
                    <h1>Hello from the honeypot</h1>
                </body>
            </html>
            """

    def start(self, host: str, port: int):
        uvicorn.run(self.app, host=host, port=port)

if __name__ == "__main__":
    server: HoneypotWebserver = HoneypotWebserver()
    server.start("0.0.0.0", 80)