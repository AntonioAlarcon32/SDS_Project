from dnserver import DNSServer

server = DNSServer.from_toml('records_honeypot.toml', port=53, upstream=None)
server.start()
while True:
    pass