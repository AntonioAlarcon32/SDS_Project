import logging
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
import socket

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

failed_attempts = {}
controller_address = "10.100.100.100"
controller_port = 9999
fail_threshold = 3

def send_udp_packet(dst_ip, dst_port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode('utf-8'), (dst_ip, dst_port))
    sock.close()

class MyHandler(FTPHandler):

    def on_connect(self):
        print("connected")
    
    def on_login_failed(self, username, password):
        remote_ip = self.remote_ip
        print(f"FAILED FROM {self.remote_ip}")
        if remote_ip in failed_attempts:
            failed_attempts[remote_ip] += 1
            if failed_attempts[remote_ip] > fail_threshold:
                send_udp_packet(controller_address, controller_port, f"ban;{remote_ip}")
                print("User banned, packet sent to the controller")
        else:
            failed_attempts[remote_ip] = 1
        print(f"Failed attempts from {remote_ip}: {failed_attempts[remote_ip]}")


def main():
    authorizer = DummyAuthorizer()
    
    # Add a user with full permissions
    authorizer.add_user("ftpuser", "ftppassword", "/home/ftpuser", perm="elradfmw")
    
    # Add an anonymous user with read-only permissions
    # authorizer.add_anonymous("/home/nobody")
    
    handler = MyHandler
    handler.authorizer = authorizer
    
    # Define a customized banner (optional)
    handler.banner = "pyftpdlib based ftpd ready."
    
    # Instantiate the FTP server
    address = ("0.0.0.0", 21)
    server = FTPServer(address, handler)
    
    # Set a limit for connections
    server.max_cons = 256
    server.max_cons_per_ip = 5
    
    # Start the FTP server
    server.serve_forever()

if __name__ == "__main__":
    main()
