import socket

def main():
    host = "0.0.0.0"
    port = 8080

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()

        print("Server listening on port 8080...")

        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(f"Received from Rust: {data.decode()}")

                message = input("Python Server: ")
                conn.sendall(message.encode())

                if message.lower() == 'quitter':
                    break

if __name__ == "__main__":
    main()
