# Additional PaySys Executables Reverse Engineering Analysis

This document contains the reverse engineering analysis of two additional PaySys executables from `paysys.zip`: `vzopaysys.exe` and `KG_SimulatePaysys_FS.exe`.

## Executable Overview

### vzopaysys.exe
- **Size**: 106,496 bytes  
- **Type**: PE32 executable (console) Intel 80386, for MS Windows, 5 sections
- **Copyright**: VzoGame 2014 - Version: 1.0.0.0 (Build at Nov 13 2014 23:13:25)
- **Description**: VzoGame-branded PaySys server implementation

### KG_SimulatePaysys_FS.exe  
- **Size**: 98,304 bytes
- **Type**: PE32 executable (console) Intel 80386, for MS Windows, 5 sections  
- **Copyright**: KingSoft 2012 and LaoDai, yh: trami_2012
- **Description**: KingSoft/LaoDai-branded PaySys server implementation

## Complete Protocol Handler Functions

Both executables implement a comprehensive set of protocol handlers, revealing the complete PaySys protocol:

### Bishop-to-PaySys (b2p) Handlers

1. **b2p_bishop_identity_verify** - Bishop server identity verification
2. **b2p_bishop_reconnect_identity_verify** - Bishop reconnection verification
3. **b2p_change_account_state** - Account state modification
4. **b2p_ext_points_operation** - Extended points operations
5. **b2p_gameworld_2_paysys** - Game world to PaySys communication
6. **b2p_ib_player_buy_item** - Item shop purchase
7. **b2p_ib_player_buy_multi_item** - Bulk item purchase
8. **b2p_ib_player_identity_verify** - Item shop player verification
9. **b2p_ib_player_use_item** - Item usage
10. **b2p_ib_player_use_multi_item** - Bulk item usage
11. **b2p_ping** - Keepalive ping
12. **b2p_player_exchange** - Coin exchange operations
13. **b2p_player_exchange_ex** - Extended coin exchange
14. **b2p_player_freeze_fee** - Account freezing/fee operations
15. **b2p_player_identity_verify** - Player login verification
16. **b2p_player_leave_game** - Player logout (vzopaysys.exe)
17. **b2p_player_enter_game** - Player login (KG_SimulatePaysys_FS.exe)
18. **b2p_player_passpod_verify_ex** - MiBao/PassPod verification
19. **b2p_player_query_transfer** - Transfer query operations
20. **b2p_player_set_charge_flag** - Charge flag setting
21. **b2p_player_transfer** - Coin transfer operations
22. **b2p_use_spreader_cdkey** - CD-Key/gift code redemption

### PaySys-to-Bishop (p2b) Handlers

1. **p2b_get_zone_charge_flag** - Zone charge flag retrieval
2. **p2b_ping** - Response ping

## Protocol Structure Analysis

### Core Protocol Header
```c
struct tagProtocolHeader {
    // 4-byte header structure (size determined from error messages)
    // Contains message type, length, and sequence information
};
```

### Key Data Structures
Based on the `sizeof()` references found in both executables:

1. **KAccountFreezeFee** - Account freeze/fee operations
2. **KAccountExchange** - Basic coin exchange
3. **KAccountExchangeEx** - Extended coin exchange  
4. **KAccountTransfer** - Coin transfer operations
5. **KAccountQueryTransfer** - Transfer queries
6. **KChangeAccountState** - Account state changes
7. **TAccountCDKEY** - CD-Key/gift code structure
8. **KGetZoneChargeFlag** - Zone charge flag structure

## Database Operations

### vzopaysys.exe SQL Operations
More comprehensive database operations including:

```sql
-- Extended points management
UPDATE account SET nExtpoin0 = %d WHERE username='%s'
UPDATE account SET nExtpoin1 = %d WHERE username='%s'  
UPDATE account SET nExtpoin2 = %d WHERE username='%s'
UPDATE account SET nExtpoin4 = nExtpoin4 + %d WHERE username='%s'
UPDATE account SET nExtpoin5 = nExtpoin5 + %d WHERE username='%s'
UPDATE account SET nExtpoin6 = nExtpoin6 + %d WHERE username='%s'
UPDATE account SET nExtpoin7 = nExtpoin7 + %d WHERE username='%s'

-- Security and tracking
UPDATE account SET bklactivenew = bklactivenew + %d WHERE username='%s'
UPDATE account SET trytohack = trytohack + 1 WHERE username='%s'
UPDATE account SET LastLoginIP = '%d' WHERE username='%s'

-- Card system
SELECT szCardSeri,szAccount FROM Card WHERE szCardSeri = '%s'
SELECT `nOk` FROM `Card` WHERE `szCardSeri` = '%s'
```

### KG_SimulatePaysys_FS.exe SQL Operations
Simpler card-focused operations:
```sql
SELECT szCardSeri,szAccount FROM Card WHERE szCardSeri = '%s'
UPDATE `Card` SET `nOk` = 1 WHERE `szCardSeri` = '%s'
SELECT `nOk` FROM `Card` WHERE `szCardSeri` = '%s'
```

## Key Differences Between Executables

| Feature | vzopaysys.exe | KG_SimulatePaysys_FS.exe |
|---------|---------------|-------------------------|
| **Brand** | VzoGame 2014 | KingSoft/LaoDai 2012 |
| **Database Ops** | Extensive account management | Basic card operations |
| **Player Events** | `b2p_player_leave_game` | `b2p_player_enter_game` |
| **Security** | Hack attempt tracking | Basic functionality |
| **Ext Points** | 8 different point types | Limited support |
| **MySQL Error** | "Cannot Connect to Mysql Server, please check your config" | No specific MySQL error message |

## Startup Messages

### vzopaysys.exe
```
[Paysys] Payment System Jx2Online Start....
[Paysys] Chuong trinh duoc xay dung cho game VLTK 2....
[Paysys] Disconnected !!!
[Paysys].....Starting the Paysys...
[Paysys] Running Completed!....
```

### KG_SimulatePaysys_FS.exe  
```
[Paysys] Manager Is Starting....
[Paysys] Is Disconnected and Exit When you Press anykey.
[Paysys].....Started !!! Running Complete..
[Paysys] This Server is Code and Build by LaoDai
[Paysys] Copyright KingSoft 2012 and LaoDai , yh: trami_2012
```

## Implementation Impact

With access to these executables, we now have:

1. **Complete Protocol Map**: All 22+ protocol handlers identified
2. **Full Database Schema**: Extended points system, card system, security features
3. **Multiple Implementation Variants**: Different feature sets for different deployments
4. **Enhanced Security Features**: Hack detection, IP tracking, multiple verification methods

This analysis provides a comprehensive foundation for implementing a complete PaySys server replacement that supports the full feature set of the original system.

## Next Steps

1. Update the reverse-engineered server to implement all identified handlers
2. Implement the extended database schema with all point types
3. Add the card/CD-Key system functionality
4. Implement the complete item shop (IB) system
5. Add MiBao/PassPod verification system
6. Create comprehensive protocol testing suite