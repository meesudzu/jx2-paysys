# JX2 Payment System Server

A C++ implementation of the JX2 payment system server, reverse engineered from the original binaries.

## Overview

This project implements a new payment system server for JX2 (Jx2) game servers, compatible with the original Bishop client and protocol. The implementation is based on reverse engineering of the original payment system binaries:

- **Priority Logic Sources:**
  1. `KG_SimulatePaysys_FS.exe` (highest priority)
  2. `vzopaysys.exe` (medium priority)  
  3. `paysys` (Linux binary, lowest priority)

## Implementation Status

✅ **Completed:**
- C++ project structure with modular design
- TCP server listening on configurable port (default: 8000)
- MySQL database integration for account management
- Configuration management (INI file parsing)
- Protocol message parsing and routing
- Multi-threaded client handling
- Bishop login authentication
- Test client for protocol verification
- PCAP analysis tools for protocol reverse engineering
- Successfully tested with original Bishop client (connection established)

🔄 **In Progress:**
- Message encryption/decryption (PCAP analysis shows XOR-based encryption)
- Full protocol compatibility with original Bishop client
- Enhanced error handling and logging

📋 **Planned:**
- Complete protocol encryption implementation
- Additional message types (user operations, item purchasing)
- Performance optimization
- Security hardening

## Features

- TCP server with configurable binding (IP/port)
- MySQL database connectivity with connection pooling
- Protocol handling for Bishop client connections
- Support for user authentication, login/logout operations
- Configurable return codes for different operations
- Multi-threaded client handling with proper cleanup
- Test mode operation (works without database)

## Building

### Requirements

- C++11 compatible compiler
- MySQL development libraries
- pthreads support

### Using Make

```bash
make all
```

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

## Configuration

Edit `paysys.ini` to configure the server:

```ini
[Paysys]
szPaysysIPAddress=127.0.0.1
nPaysysPort=8000
nMaxAcceptEachWait=512
nMaxRecvBufSizePerSocket=2048
nMaxSendBufSizePerSocket=2048
nMaxEventCount=512

[Mysql]
Host=127.0.0.1
Username=root
Password=1234
DBName=jx2_paysys
```

## Database Setup

1. Create MySQL database:
```sql
CREATE DATABASE jx2_paysys;
```

2. Import the provided schema:
```bash
mysql -u root -p jx2_paysys < paysys-win/paysys.sql
```

## Running

```bash
./bin/paysys
```

The server will start and listen on the configured port for Bishop client connections.

## Testing

### Using the Test Client

```bash
python3 test_client.py
```

### Using the Original Bishop Client

The original Bishop client can connect to the server:

```bash
cd bishop
./KG_BishopD
```

Note: Full compatibility requires implementing the encryption protocol found in the PCAP analysis.

## Protocol Analysis

The implementation is based on analysis of:
- Network packet captures (`player-login.pcap`, `bishop-connect-capture.pcap`)
- Original binary reverse engineering
- Configuration files from original system

### PCAP Analysis

Use the provided analyzer to examine network traffic:

```bash
python3 pcap_analyzer.py bishop-connect-capture.pcap
```

The analysis reveals:
- Messages use XOR-based encryption
- Protocol appears to use 4-byte message type headers (little-endian)
- Bishop authentication uses username/password pairs
- Multiple message types for different operations

## Project Structure

```
src/
├── main.cpp              # Main application entry point
├── config_manager.h/cpp  # Configuration file handling
├── database_manager.h/cpp # MySQL database operations
├── paysys_server.h/cpp   # TCP server implementation
└── protocol_handler.h/cpp # JX2 protocol message handling

tools/
├── test_client.py        # Python test client
└── pcap_analyzer.py      # PCAP analysis tool
```

## Achievements

1. **Successful Reverse Engineering**: Created a working C++ implementation that can accept connections from the original Bishop client
2. **Protocol Compatibility**: Basic message structure and routing implemented
3. **Database Integration**: MySQL connectivity for account management
4. **Modular Architecture**: Clean, maintainable code structure
5. **Testing Infrastructure**: Tools for verification and analysis

## Next Steps

1. Complete the encryption/decryption implementation based on PCAP analysis
2. Add support for all message types found in the original system
3. Implement robust error handling and logging
4. Performance testing and optimization
5. Security audit and hardening

## License

This project is for educational and research purposes, based on reverse engineering of existing game server binaries.