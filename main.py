import sys

# Import TCP
from tcp import run_tcp_server, tcp_client

# Import TLS
from tls import start_server, start_client

# Import UDP
from udp import run_udp_server, udp_client

def main():
    while True:
        
            print("\n🌐 OpenChat Menu:")
            print("0 - Exit")
            print("1 - Start TCP Server")
            print("2 - Start TLS Server")
            print("3 - Start UDP Server")
            print("4 - Connect as TCP Client")
            print("5 - Connect as TLS Client")
            print("6 - Connect as UDP Client")
            while True:
                choice = input("Select option: ").strip()
            
                # Exit
                if choice == "0":
                    print("Goodbye 👋")
                    sys.exit(0)

                # TCP Server
                elif choice == "1":
                    print("\n[System] Starting TCP Server...")
                    run_tcp_server()
                    break
                # TLS Server
                elif choice == "2":
                    print("\n[System] Starting TLS Server...")
                    start_server()
                    break
                    
                # UDP Server
                elif choice == "3":
                    print("\n[System] Starting UDP Server...")
                    run_udp_server()
                    break
                # TCP Client
                elif choice == "4":
                    ip = input("Server IP: ").strip() or "127.0.0.1"
                    tcp_client(ip)
                    break
                # TLS Client
                elif choice == "5":
                    ip = input("Server IP: ").strip() or "127.0.0.1"
                    start_client(ip)
                    break
                
                # UDP Client
                elif choice == "6":
                    ip = input("Server IP: ").strip() or "127.0.0.1"
                    udp_client(ip)
                    break

                else:
                    print("[System] Invalid choice, try again.")
if __name__ == "__main__":
        main()