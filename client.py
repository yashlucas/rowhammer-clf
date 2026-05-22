import socket

HOST = "127.0.0.1"
PORT = 5000

def recv_until_prompt(sock):
    data = b""
    while not data.endswith(b"> "):
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="ignore")

with socket.create_connection((HOST, PORT)) as s:
    print(recv_until_prompt(s), end="")

    while True:
        cmd = input()
        s.sendall((cmd + "\n").encode())

        if cmd.upper() == "EXIT":
            break

        response = recv_until_prompt(s)
        print(response, end="")