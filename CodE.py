import subprocess as sp
import platform
import socket
import threading
import ssl
import time

def host_discover(ip):
    system_platform = platform.system().lower()

    if system_platform == "windows":
        command = ["ping", "-n", "1", ip]
    else:
        command = ["ping", "-c", "1", ip]

    try:
        result = sp.run(command, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"Host {ip} is available for further enumeration.")
            return True
        else:
            print(f"Host {ip} is not available.")
            return False
    except Exception as e:
        print(f"Error checking host availability: {e}")
        return False

def scan_port(target_ip, port, retries=3, timeout=10):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    attempt = 0
    while attempt < retries:
        try:
            result = sock.connect_ex((target_ip, port))

            if result == 0:
                print(f"Port {port} is open, attempting to grab banner...")

                if port == 80 or port == 443:
                    try:
                        if port == 443:
                            context = ssl.create_default_context()
                            sock = context.wrap_socket(sock, server_hostname=target_ip)

                        http_request = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
                        sock.sendall(http_request.encode())

                        banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()

                        if banner:
                            print(f"Port {port} banner: {banner}")
                        else:
                            print(f"Port {port} is open, but no banner received.")

                    except socket.timeout:
                        print(f"Port {port} is open, but timed out while waiting for HTTP banner.")
                    except ssl.SSLError as ssl_error:
                        print(f"SSL error on port {port}: {ssl_error}")
                    except Exception as e:
                        print(f"Error grabbing HTTP banner from port {port}: {e}")

                elif port == 22:
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                        if banner:
                            print(f"Port {port} (SSH) banner: {banner}")
                        else:
                            print(f"Port {port} is open, but no SSH banner received.")

                    except socket.timeout:
                        print(f"Port {port} (SSH) is open, but timed out while waiting for banner.")
                    except Exception as e:
                        print(f"Error grabbing SSH banner from port {port}: {e}")

                elif port == 20:
                    try:
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()

                        if banner:
                            print(f"Port {port} (FTP) banner: {banner}")
                        else:
                            print(f"Port {port} is open, but no FTP banner received.")

                    except socket.timeout:
                        print(f"Port {port} (FTP) is open, but timed out while waiting for banner.")
                    except Exception as e:
                        print(f"Error grabbing FTP banner from port {port}: {e}")

                else:
                    print(f"Port {port} is open, but no specific banner grab logic implemented for this port.")

                return  # Success, exit the retry loop

            else:
                print(f"Port {port} is closed or unreachable.")
                return

        except socket.timeout:
            print(f"Attempt {attempt + 1} of {retries}: Timeout on port {port}")
        except Exception as e:
            print(f"Error with socket connection to {target_ip} on port {port}: {e}")
        
        attempt += 1
        time.sleep(1)  # Wait a bit before retrying

    print(f"Failed to connect to port {port} after {retries} attempts.")
    sock.close()

def port_scan(target_ip, start_port, end_port):
    threads = []
    
    for port in range(start_port, end_port + 1):
        thread = threading.Thread(target=scan_port, args=(target_ip, port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

def main():
    print("=" * 50)
    print(" " * 10 + "Welcome to the Advanced Port Scanner Tool")
    print(" " * 5 + "This tool allows you to scan open ports and detect services on a target IP.")
    print("=" * 50)
    print(" " * 10 + "Please proceed with caution and ensure you have permission to scan the target.")
    print("=" * 50)
    
    while True:
        try:
            choice = input("What would you like to do? (1: Check if host is up, 2: Scan ports, 3: Exit): ")
            
            if "1" in choice:
                ip = input("Enter the IP address to check: ")
                host_discover(ip)
            elif "2" in choice:
                ip = input("Enter the IP address to scan: ")
                result = host_discover(ip)
                if result:
                    start_port = int(input("Enter the start port to scan: "))
                    end_port = int(input("Enter the end port to scan: "))
                    print("Port Status  Service")
                    port_scan(ip, start_port, end_port)
                else:
                    print("The host is not reachable.")
            elif "3" in choice:
                print("Exiting the tool. Stay safe!")
                break
            else:
                print("Invalid choice, please select a valid option.")
        except KeyboardInterrupt:
            print("\nOperation interrupted by user. Exiting the tool.")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
