# Protocol Documentation

## JX2 Paysys Protocol Specification

This document describes the reverse-engineered protocol used by the JX2 payment system.

### Overview

The JX2 paysys uses a TCP-based binary protocol with the following characteristics:
- **Port**: 8000 (configurable)
- **Encoding**: Little-endian binary
- **Encryption**: XOR cipher with fixed 16-byte key
- **Packet Structure**: [Size:2][Type:2][Data:Variable]

### XOR Encryption Key

```
45 73 77 29 2F DA 9A 21 10 52 B1 9C 70 93 0E A0
```

This 16-byte key repeats for longer data blocks.

### Packet Types

#### Bishop Login (0x0020)

**Purpose**: Authentication of Bishop (game server) clients

**Structure**:
```
Offset | Size | Field     | Description
-------|------|-----------|------------------
0x00   | 2    | Size      | Total packet size (34)
0x02   | 2    | Type      | Packet type (0x0020)
0x04   | 4    | Unknown1  | Always 0x00000000
0x08   | 4    | Unknown2  | Variable value
0x0C   | 4    | Unknown3  | Session/timestamp?
0x10   | 16   | BishopID  | Bishop identifier
```

**Example** (from PCAP):
```
22 00 20 00 00 00 00 00 00 00 F5 4D 3F C9 5A CF
B2 5E 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00
```

#### Bishop Response (0x0021)

**Purpose**: Response to Bishop login

**Structure**:
```
Offset | Size | Field  | Description
-------|------|--------|------------------
0x00   | 2    | Size   | Total packet size (5)
0x02   | 2    | Type   | Packet type (0x0021)
0x04   | 1    | Result | 0=success, >0=error
```

#### User Login (0x42FF)

**Purpose**: User authentication from game client

**Structure**:
```
Offset | Size | Field         | Description
-------|------|---------------|------------------
0x00   | 2    | Size          | Total packet size
0x02   | 2    | Type          | Packet type (0x42FF)
0x04   | N    | EncryptedData | XOR encrypted login data
```

**Decrypted Data Structure**:
```
Offset | Size | Field     | Description
-------|------|-----------|------------------
0x00   | 9    | Header    | 00 0A 00 02 00 01 00 00 00
0x09   | N    | Username  | Null-terminated string
       | M    | Padding   | Null bytes to offset 45
0x2D   | 32   | Password  | MD5 hash (uppercase hex)
       | R    | Unknown   | Additional session data
```

**Example Decrypted Login**:
- Username: "admin" 
- Password: "5D41402ABC4B2A76B9719D911017C592" (MD5 of "hello")

#### User Response (0xA8FF)

**Purpose**: Response to user login

**Structure**:
```
Offset | Size | Field         | Description
-------|------|---------------|------------------
0x00   | 2    | Size          | Total packet size
0x02   | 2    | Type          | Packet type (0xA8FF)
0x04   | N    | EncryptedData | XOR encrypted response
```

**Decrypted Response Structure**:
```
Offset | Size | Field   | Description
-------|------|---------|------------------
0x00   | 1    | Result  | 0=success, >0=error
0x01   | N    | Message | Null-terminated status message
```

**Result Codes**:
- 0: Login successful
- 1: Parse error
- 2: Database error  
- 3: Invalid credentials
- 4: Account suspended

### Network Flow

#### Bishop Connection Flow
1. Bishop → Paysys: Bishop Login (0x0020)
2. Paysys → Bishop: Bishop Response (0x0021)

#### User Login Flow  
1. Client → Paysys: User Login (0x42FF) with encrypted credentials
2. Paysys → Client: User Response (0xA8FF) with encrypted result

### Implementation Notes

1. **Endianness**: All multi-byte integers are little-endian
2. **Strings**: Null-terminated, padded to fixed offsets
3. **Password Hashing**: MD5 uppercase hexadecimal
4. **Connection Handling**: Each request opens a new connection
5. **Error Handling**: Non-zero result codes indicate errors

### Security Considerations

1. **Weak Encryption**: XOR with fixed key provides minimal security
2. **MD5 Hashing**: Deprecated hash algorithm, vulnerable to collisions  
3. **No TLS**: Protocol transmits encrypted credentials over plain TCP
4. **Key Reuse**: Same XOR key used for all communications

### Testing

Use the provided test client to validate implementations:

```bash
# Test Bishop connection
./client bishop

# Test user login  
./client login admin hello
```

Expected responses should match the packet structures documented above.