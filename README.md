# JX2 Payment System (Go Implementation)

This is a reverse-engineered Go implementation of the JX2 payment system, reconstructed from binary files and network packet analysis.

## Overview

This project provides a complete reimplementation of the JX2 payment system server in Go, based on analysis of:
- Original binary files (Linux and Windows versions)
- Network traffic captures (PCAP files)
- Database schema reconstruction
- Protocol reverse engineering

## Architecture

The system consists of:
- **Paysys Server**: Main TCP server handling authentication and payments
- **Bishop Client**: Game server client that connects to paysys
- **Database**: MySQL database for account management
- **Protocol Handler**: XOR-encrypted packet processing

## Directory Structure

```
.
├── cmd/
│   ├── paysys/          # Main paysys server executable
│   └── test/            # Protocol testing tool
├── internal/
│   ├── config/          # Configuration management
│   ├── database/        # MySQL database layer
│   ├── protocol/        # Packet parsing and encryption
│   └── server/          # TCP server implementation
├── paysys-linux/        # Original Linux binary (reference)
├── paysys-win/          # Original Windows binaries (reference)
├── bishop/              # Original Bishop client (reference)
├── *.pcap               # Network capture files (reference)
└── database_schema.sql  # Database setup script
```

## Protocol Specification

### Packet Structure

All packets follow this structure:
```
[Size:2][Type:2][Data:Variable]
```

### Packet Types

#### Bishop Login (0x0020)
```
Size: 34 bytes
Structure:
- Header: 4 bytes (size + type)
- Unknown1: 4 bytes (always 0x00000000)
- Unknown2: 4 bytes 
- Unknown3: 4 bytes (session/timestamp?)
- Bishop ID: 16 bytes
```

#### User Login (0x42FF)
```
Size: Variable (229 bytes in captured example)
Structure:
- Header: 4 bytes (size + type)  
- Encrypted Data: XOR encrypted with repeating key
```

### XOR Encryption

The system uses XOR encryption with a 16-byte repeating key:
```
Key: 45 73 77 29 2F DA 9A 21 10 52 B1 9C 70 93 0E A0
```

Decrypted login data contains:
- Username (null-terminated string)
- Password (MD5 hash, null-terminated)
- Additional session data

## Setup Instructions

### Prerequisites

- Go 1.21 or later
- MySQL 5.7 or later

### Database Setup

1. Create MySQL database:
```sql
mysql -u root -p < database_schema.sql
```

2. Update `paysys.ini` with your database credentials:
```ini
[Database]
IP=127.0.0.1
Port=3306
UserName=root
Password=your_password
DBName=jx2_paysys
```

### Building

```bash
# Build the main server
go build ./cmd/paysys

# Build the test tool
go build ./cmd/test
```

### Running

1. Start the paysys server:
```bash
./paysys
```

2. Test with the protocol analyzer:
```bash
./test
```

## Protocol Analysis Results

From PCAP analysis, we discovered:

### Bishop Connection
- Uses simple packet structure with 16-byte identifier
- Always sends 34-byte packets
- No encryption for Bishop authentication

### Player Login
- Uses XOR encryption with fixed key
- Contains username and MD5-hashed password
- Example decrypted data shows "admin" user with password hash

### Response Packets
- Server responds with encrypted success/failure codes
- Bishop responses are unencrypted
- User responses use same XOR encryption as requests

## Testing

The test tool validates:
- Packet parsing from real PCAP data
- XOR encryption/decryption
- Username/password extraction
- Response packet generation

Example test output:
```
=== JX2 Paysys Protocol Test ===

--- Testing Bishop Login Packet ---
Packet Type: 0x0020
Packet Size: 34
Bishop ID: b25e0000000000000000000000000000

--- Testing Player Login Packet ---
Packet Type: 0x42FF  
Packet Size: 229
Parsed - Username: "admin", Password: "C4CA4238A0B923820DCC509A6F75849B"
```

## Configuration

### paysys.ini

```ini
[Paysys]
IP=127.0.0.1
Port=8000
PingCycle=10
InternalIPMask=127.0.0.0
LocalIP=

[Database]
IP=127.0.0.1
Port=3306
UserName=root
Password=1234
DBName=jx2_paysys
```

## Security Notes

- Passwords are stored as MD5 hashes (original system design)
- XOR encryption with fixed key (reverse engineered from traffic)
- No TLS/SSL (original protocol limitation)
- Account state management prevents banned user access

## Original Files Priority

As specified in the requirements, logic priority is:
1. `paysys-win/KG_SimulatePaysys_FS.exe` (highest priority)
2. `paysys-win/vzopaysys.exe` 
3. `paysys-linux/paysys` (lowest priority)

## Development

To extend the system:
1. Add new packet types to `internal/protocol/packets.go`
2. Implement handlers in `internal/protocol/handler.go`
3. Update database schema as needed
4. Test with the protocol analyzer

## Troubleshooting

### Common Issues

1. **Database connection failed**: Check MySQL credentials in `paysys.ini`
2. **Packet parsing errors**: Verify packet format matches PCAP analysis
3. **Encryption issues**: Ensure XOR key matches original implementation

### Debug Mode

Enable verbose logging by setting log level in the source code.

## License

This project is for educational and research purposes, reverse engineered from publicly available binary files.