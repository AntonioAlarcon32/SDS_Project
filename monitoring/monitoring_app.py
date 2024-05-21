import socket
import os

controller_ip ="10.0.1.3"
listen_port = 5000
ip = "0.0.0.0"

def send_ping():
    response = os.system(f"ping -c 2 10.0.1.3 &> /dev/null")

def udp_server(host, port,):
    
    # Create a UDP socket
    send_ping()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind the socket to the server address
    server_address = (host, port)
    sock.bind(server_address)
    
    print(f"Listening on {host}:{port}")
    last_alert = ""
    while True:
        data, address = sock.recvfrom(4096)
        if data.decode() != last_alert: 
            print(f"Data: {data.decode()}")
            last_alert = data.decode()

if __name__ == "__main__":

    udp_server(ip, listen_port)
