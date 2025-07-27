#!/usr/bin/env python3
"""
Simple test client for JX2 Payment System Server
Sends a basic Bishop login message to test the protocol
"""
import socket
import struct
import sys

def create_bishop_login_message():
    """Create a Bishop login message"""
    # Message type: BISHOP_LOGIN (0x01)
    msg_type = struct.pack('<I', 0x01)
    
    # Username: "bishop" (32 bytes, null-padded)
    username = b'bishop' + b'\x00' * (32 - len('bishop'))
    
    # Password: "1234" (32 bytes, null-padded)
    password = b'1234' + b'\x00' * (32 - len('1234'))
    
    return msg_type + username + password

def create_ping_message():
    """Create a ping message"""
    # Message type: PING (0xFF)
    msg_type = struct.pack('<I', 0xFF)
    return msg_type

def test_server(host='127.0.0.1', port=8000):
    """Test the payment system server"""
    try:
        # Connect to server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, port))
        
        print(f"Connected to {host}:{port}")
        
        # Test 1: Send Bishop login message
        print("Sending Bishop login message...")
        login_msg = create_bishop_login_message()
        sock.send(login_msg)
        
        # Receive response
        response = sock.recv(1024)
        if response:
            msg_type = struct.unpack('<I', response[:4])[0]
            result_code = struct.unpack('<I', response[4:8])[0]
            print(f"Bishop login response: type=0x{msg_type:02x}, result={result_code}")
        
        # Test 2: Send ping message
        print("Sending ping message...")
        ping_msg = create_ping_message()
        sock.send(ping_msg)
        
        # Receive response
        response = sock.recv(1024)
        if response:
            msg_type = struct.unpack('<I', response[:4])[0]
            result_code = struct.unpack('<I', response[4:8])[0]
            print(f"Ping response: type=0x{msg_type:02x}, result={result_code}")
        
        sock.close()
        print("Test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        host = sys.argv[1]
    else:
        host = '127.0.0.1'
    
    if len(sys.argv) > 2:
        port = int(sys.argv[2])
    else:
        port = 8000
    
    success = test_server(host, port)
    sys.exit(0 if success else 1)