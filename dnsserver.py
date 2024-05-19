from dnserver import DNSServer

server = DNSServer.from_toml('records.toml', port=5053, upstream=None)
server.start()
while True:
    pass