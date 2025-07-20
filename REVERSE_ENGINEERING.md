# Reverse Engineering Methodology for JX2 PaySys Binary

## Overview

This document explains the methodology used to reverse engineer the stripped JX2 PaySys binary (`paysys`) and create a functional source code implementation.

## Binary Analysis Process

### 1. Initial Binary Information Gathering

```bash
# Check file type and architecture
file paysys
# Result: ELF 64-bit LSB executable, x86-64, stripped

# Check dependencies
ldd paysys
# Dependencies: libmysqlclient.so.18, libstdc++.so.6, libc.so.6

# Check symbols
nm paysys
# Result: No symbols (stripped binary)

# Check dynamic symbols
objdump -T paysys
# Found MySQL and standard library functions
```

### 2. String Analysis

The most valuable information came from analyzing embedded strings:

```bash
strings paysys | grep -i "select\|insert\|update\|delete"
```

**Key Database Operations Identified:**
- `Select password From account WHERE username='%s'`
- `Select coin From account WHERE username='%s'`
- `Update account Set coin = coin + '%d' WHERE username = '%s'`

```bash
strings paysys | grep -E "On[A-Z][a-zA-Z]*Request"
```

**Protocol Request Handlers Found:**
- `OnPlayerSetChargeFlagRequest`
- `OnChangeExtPointsRequest`
- `OnFreezeCoinRequest` 
- `OnMiBaoVerifyRequest`
- `OnActivePresentCodeRequest`
- `OnAccountExchangeRequest`
- `OnGatewayVerifyRequest`
- `OnGateWayReVerityRequest`
- `OnAccountVerifyRequest`

### 3. Protocol Structure Analysis

From `sizeof` checks in the binary:
- `pRequest->Size == sizeof(KServerAccountUserLoginInfo2)`
- `uDataLen == (sizeof(KGameworld2Paysys) + sizeof(KAccountActivePresentCode))`
- `uBufferSize >= sizeof(tagProtocolHeader)`
- `uBufferSize <= 65500` (Maximum packet size)

### 4. Configuration Analysis

Analysis of `paysys.ini` revealed:
- Server listens on configurable IP/Port (default: 127.0.0.1:8000)
- MySQL connection parameters
- Ping cycle configuration
- IP masking for security

### 5. Database Schema Analysis

From `jx2_paysys.sql`:
- Primary table: `account` with fields for username, password, coins
- Password appears to be MD5 hashed
- Additional fields for security, locking, and extended points

## Reverse Engineering Challenges

### 1. Stripped Binary Limitations
- **No function names**: Had to infer from string patterns
- **No variable names**: Deduced from SQL query formats  
- **No debugging symbols**: Relied on dynamic symbol analysis
- **Optimized code**: Some logic may be inlined or optimized away

### 2. Protocol Structure Inference
- **Binary protocol**: Had to guess packet structure from sizeof checks
- **Network endianness**: Assumed little-endian based on x86-64 architecture
- **Data types**: Inferred from string formatting and MySQL column types

### 3. State Management
- **Connection tracking**: Implemented basic connection ID system
- **Session state**: Simplified compared to original (likely more complex)
- **Error handling**: Basic implementation based on observed patterns

## Implementation Strategy

### 1. Protocol Layer
```javascript
// Inferred packet structure
{
    size: uint16,      // Total packet size (from sizeof checks)
    type: uint16,      // Request type (from handler function names)
    payload: bytes[]   // Variable length data
}
```

### 2. Request Handling
Based on function name patterns, implemented handlers:
- Account verification using database password comparison
- Coin exchange operations with database updates
- Gateway verification (simplified implementation)

### 3. Database Integration
Direct implementation of observed SQL queries:
- Password verification with prepared statements
- Coin balance queries and updates  
- Security considerations for SQL injection prevention

## Limitations of Reverse-Engineered Implementation

### 1. Incomplete Protocol Coverage
- Only implemented handlers found in string analysis
- Some binary-only logic may be missing
- Error conditions may differ from original

### 2. Simplified State Management
- Original may have complex session tracking
- Security features may be reduced
- Performance optimizations not replicated

### 3. Data Structure Approximations
- Packet structures are educated guesses
- Field sizes and alignments may differ
- Endianness handling may need adjustment

## Testing and Validation

### 1. Protocol Compatibility Testing
```bash
# Test with original database
node test-reversed-server.js

# Compare with proxy logs
node protocol-analyzer.js
```

### 2. Database Compatibility
- Uses same MySQL schema as original
- Maintains data consistency with existing accounts
- Password hashing compatibility verified

### 3. Performance Considerations
- Single-threaded vs original (likely multi-threaded)
- Memory usage patterns differ
- Network handling may be less optimized

## Future Improvements

### 1. Dynamic Analysis
- Use proxy logs to refine protocol understanding
- Capture real client interactions for validation
- Identify missing request types

### 2. Binary Analysis Tools
- Use Ghidra/IDA Pro for deeper analysis if available
- Dynamic debugging with GDB for runtime analysis
- Memory dump analysis during execution

### 3. Protocol Refinement
- Implement missing request handlers as discovered
- Improve packet structure accuracy
- Add proper error handling and edge cases

## Conclusion

This reverse engineering effort successfully extracted enough information from the stripped binary to create a functional PaySys server implementation. While not 100% feature-complete, it provides:

1. **Core functionality**: Account verification and coin management
2. **Database compatibility**: Works with existing MySQL schema
3. **Protocol foundation**: Extensible framework for additional features
4. **Development platform**: Base for further reverse engineering efforts

The implementation serves as both a functional replacement and a research platform for understanding the original PaySys protocol through continued analysis and testing.