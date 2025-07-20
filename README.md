# JX2 PaySys Reverse Engineered Server

This is a reverse-engineered implementation of the JX2 PaySys server based on binary analysis of the original stripped executable.

## Reverse Engineering Analysis

### Binary Information
- **File**: paysys (ELF 64-bit LSB executable, stripped)
- **Size**: 181,456 bytes
- **Architecture**: x86-64
- **Libraries**: MySQL client, libstdc++

### Extracted Protocol Information

From strings analysis of the binary, we identified these key request handlers:
- `OnPlayerSetChargeFlagRequest`
- `OnChangeExtPointsRequest` 
- `OnFreezeCoinRequest`
- `OnMiBaoVerifyRequest`
- `OnActivePresentCodeRequest`
- `OnAccountExchangeRequest`
- `OnGatewayVerifyRequest`
- `OnGateWayReVerityRequest`
- `OnAccountVerifyRequest`

### Database Operations Identified
```sql
-- Account login verification
Select password From account WHERE username='%s'

-- Get account coins
Select coin From account WHERE username='%s'

-- Update account coins
Update account Set coin = coin + '%d' WHERE username = '%s'
```

### Protocol Structures
Based on sizeof checks in the binary:
- `KServerAccountUserLoginInfo2` - Account login structure
- `KGameworld2Paysys` - Game world to PaySys communication
- `KAccountActivePresentCode` - Gift code activation
- `tagProtocolHeader` - Base protocol header

## Implementation

The reverse-engineered server implements the core functionality observed in the binary:
1. TCP server listening on port 8000
2. MySQL database connectivity for account operations
3. Protocol packet handling with proper structure sizes
4. Account verification and coin management
5. Gateway authentication system

## Usage

```bash
# Start the reverse-engineered server
node paysys-server.js

# Or use Node.js with specific configuration
npm start
```

## Limitations

This reverse-engineered implementation:
- May not include all edge cases handled by the original binary
- Protocol structures are approximated based on string analysis
- Some advanced features may be missing due to binary obfuscation
- Error handling may differ from the original implementation

## Compatibility

The server maintains compatibility with:
- Existing MySQL database schema (`jx2_paysys.sql`)
- Original configuration format (`paysys.ini`)
- Client protocol expectations