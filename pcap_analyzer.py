#!/usr/bin/env python3
"""
Simple PCAP analyzer for JX2 payment system protocol
Extracts TCP payload data from PCAP files
"""
import struct
import sys

def parse_pcap(filename):
    """Parse PCAP file and extract TCP payloads"""
    with open(filename, 'rb') as f:
        data = f.read()
    
    # PCAP global header (24 bytes)
    if len(data) < 24:
        print("File too small")
        return
    
    magic = struct.unpack('<I', data[0:4])[0]
    if magic != 0xa1b2c3d4:
        print("Not a valid PCAP file")
        return
    
    print(f"Analyzing {filename}")
    print(f"File size: {len(data)} bytes")
    
    offset = 24  # Skip global header
    packet_num = 0
    
    while offset < len(data):
        if offset + 16 > len(data):
            break
            
        # Packet header (16 bytes)
        ts_sec = struct.unpack('<I', data[offset:offset+4])[0]
        ts_usec = struct.unpack('<I', data[offset+4:offset+8])[0]
        incl_len = struct.unpack('<I', data[offset+8:offset+12])[0]
        orig_len = struct.unpack('<I', data[offset+12:offset+16])[0]
        
        offset += 16
        packet_num += 1
        
        if offset + incl_len > len(data):
            break
            
        packet_data = data[offset:offset+incl_len]
        offset += incl_len
        
        print(f"\nPacket {packet_num}:")
        print(f"  Length: {incl_len} bytes")
        print(f"  Timestamp: {ts_sec}.{ts_usec:06d}")
        
        # Parse Ethernet header (14 bytes)
        if len(packet_data) < 14:
            continue
            
        eth_type = struct.unpack('>H', packet_data[12:14])[0]
        if eth_type != 0x0800:  # Not IPv4
            continue
            
        # Parse IP header
        if len(packet_data) < 34:
            continue
            
        ip_header = packet_data[14:34]
        ip_version = (ip_header[0] >> 4) & 0xF
        ip_header_len = (ip_header[0] & 0xF) * 4
        ip_protocol = ip_header[9]
        
        if ip_version != 4 or ip_protocol != 6:  # Not IPv4 TCP
            continue
            
        # Parse TCP header
        tcp_start = 14 + ip_header_len
        if len(packet_data) < tcp_start + 20:
            continue
            
        tcp_header = packet_data[tcp_start:tcp_start+20]
        src_port = struct.unpack('>H', tcp_header[0:2])[0]
        dst_port = struct.unpack('>H', tcp_header[2:4])[0]
        tcp_header_len = ((tcp_header[12] >> 4) & 0xF) * 4
        
        # Extract TCP payload
        payload_start = tcp_start + tcp_header_len
        if payload_start < len(packet_data):
            payload = packet_data[payload_start:]
            if len(payload) > 0:
                print(f"  TCP: {src_port} -> {dst_port}")
                print(f"  Payload length: {len(payload)} bytes")
                
                # Print payload as hex
                if len(payload) <= 64:
                    hex_str = ' '.join(f'{b:02x}' for b in payload)
                    print(f"  Payload: {hex_str}")
                else:
                    hex_str = ' '.join(f'{b:02x}' for b in payload[:32])
                    print(f"  Payload (first 32 bytes): {hex_str}...")
                
                # Try to decode as ASCII
                try:
                    ascii_str = payload.decode('ascii', errors='replace')
                    print(f"  ASCII: {repr(ascii_str[:64])}")
                except:
                    pass
                
                # Check for possible message patterns
                if len(payload) >= 4:
                    msg_type = struct.unpack('<I', payload[0:4])[0]
                    print(f"  Possible message type (little-endian): 0x{msg_type:08x}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_analyzer.py <pcap_file>")
        sys.exit(1)
    
    parse_pcap(sys.argv[1])