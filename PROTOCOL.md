# Protocol Documentation

## JX2 Paysys Protocol Specification

This document describes the reverse-engineered protocol used by the JX2 payment system.

### Overview

The JX2 paysys uses a TCP-based binary protocol with the following characteristics:
- **Port**: 8000 (configurable)
- **Encoding**: Little-endian binary
- **Encryption**: XOR cipher with fixed 16-byte key
- **Packet Structure**: [Size:2][Type:2][Data:Variable]

### XOR Encryption Keys

The JX2 paysys protocol uses XOR encryption with multiple keys for different scenarios:

#### Standard Key (16 bytes)
```
45 73 77 29 2F DA 9A 21 10 52 B1 9C 70 93 0E A0
```
Used for traditional admin/user logins. Successfully decrypts packets from `player-login.pcap`.

#### Alternative Key (16 bytes)  
```
A5 AE C3 17 FB A5 AD AD 69 2B A7 9D 67 0C 51 0E
```
Discovered from `tester_1_create_character_and_login_game.pcap`. Auto-detected through repeating pattern analysis.

#### Dynamic Key Detection

The implementation includes automatic key detection:
- Pattern-based extraction from repeating 16-byte chunks
- Quality scoring to select the best decryption result
- Fallback to known keys if auto-detection fails

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

#### Character Creation (0xDDFF)

**Purpose**: Character creation request

**Structure**:
```
Offset | Size | Field         | Description
-------|------|---------------|------------------
0x00   | 2    | Size          | Total packet size (229 bytes)
0x02   | 2    | Type          | Packet type (0xDDFF)
0x04   | 225  | EncryptedData | XOR encrypted character data
```

#### Player Verification (0x26FF)

**Purpose**: Player verification during login sequence

**Structure**:
```
Offset | Size | Field | Description
-------|------|-------|------------------
0x00   | 2    | Size  | Total packet size (7 bytes)
0x02   | 2    | Type  | Packet type (0x26FF)
0x04   | 3    | Data  | Verification data
```

#### Character Selection (0x50FF)

**Purpose**: Character selection request

**Structure**:
```
Offset | Size | Field | Description
-------|------|-------|------------------
0x00   | 2    | Size  | Total packet size (7 bytes)
0x02   | 2    | Type  | Packet type (0x50FF)
0x04   | 3    | Data  | Selection data
```

#### Character Data (0xDBFF)

**Purpose**: Character data exchange

**Structure**:
```
Offset | Size | Field         | Description
-------|------|---------------|------------------
0x00   | 2    | Size          | Total packet size (61 bytes)
0x02   | 2    | Type          | Packet type (0xDBFF)
0x04   | 57   | EncryptedData | XOR encrypted character info
```

#### Session Confirmation (0x9DFF)

**Purpose**: Alternative session confirmation

**Structure**:
```
Offset | Size | Field         | Description
-------|------|---------------|------------------
0x00   | 2    | Size          | Total packet size (47 bytes)
0x02   | 2    | Type          | Packet type (0x9DFF)
0x04   | 43   | EncryptedData | XOR encrypted session data
```

### Network Flow

#### Bishop Connection Flow
1. Bishop → Paysys: Bishop Login (0x0020)
2. Paysys → Bishop: Bishop Response (0x0021)

#### User Login Flow  
1. Client → Paysys: User Login (0x42FF) with encrypted credentials
2. Paysys → Client: User Response (0xA8FF) with encrypted result

#### Character Management Flow
1. Client → Paysys: Player Verification (0x26FF)
2. Paysys → Client: Verification Response
3. Client → Paysys: Character Creation (0xDDFF) with encrypted character data
4. Paysys → Client: Creation Response
5. Client → Paysys: Character Selection (0x50FF)
6. Paysys → Client: Selection Response
7. Client → Paysys: Character Data (0xDBFF) with encrypted character info
8. Paysys → Client: Character Data Response
9. Client → Paysys: Session Confirmation (0x9DFF)
10. Paysys → Client: (No response required)

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