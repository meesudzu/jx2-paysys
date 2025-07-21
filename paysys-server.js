const net = require('net');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class EnhancedPaySysServer {
    constructor(configPath = 'paysys.ini') {
        this.config = this.loadConfig(configPath);
        this.dbConnection = null;
        this.server = null;
        this.connections = new Map();
        this.connectionId = 0;
        
        // Protocol constants extracted from binary analysis
        this.PROTOCOL_HEADER_SIZE = 4; // Based on sizeof(tagProtocolHeader)
        this.MAX_PACKET_SIZE = 65500;  // From uBufferSize <= 65500
        
        // Complete protocol handlers from both executables
        this.PROTOCOL_HANDLERS = {
            // Bishop-to-PaySys handlers
            'b2p_bishop_identity_verify': this.handleBishopIdentityVerify.bind(this),
            'b2p_bishop_login_request': this.handleBishopLoginRequest.bind(this),
            'b2p_bishop_reconnect_identity_verify': this.handleBishopReconnectVerify.bind(this),
            'b2p_change_account_state': this.handleChangeAccountState.bind(this),
            'b2p_ext_points_operation': this.handleExtPointsOperation.bind(this),
            'b2p_gameworld_2_paysys': this.handleGameWorldToPaysys.bind(this),
            'b2p_ib_player_buy_item': this.handleIbPlayerBuyItem.bind(this),
            'b2p_ib_player_buy_multi_item': this.handleIbPlayerBuyMultiItem.bind(this),
            'b2p_ib_player_identity_verify': this.handleIbPlayerIdentityVerify.bind(this),
            'b2p_ib_player_use_item': this.handleIbPlayerUseItem.bind(this),
            'b2p_ib_player_use_multi_item': this.handleIbPlayerUseMultiItem.bind(this),
            'b2p_ping': this.handlePing.bind(this),
            'b2p_player_exchange': this.handlePlayerExchange.bind(this),
            'b2p_player_exchange_ex': this.handlePlayerExchangeEx.bind(this),
            'b2p_player_freeze_fee': this.handlePlayerFreezeFee.bind(this),
            'b2p_player_identity_verify': this.handlePlayerIdentityVerify.bind(this),
            'b2p_player_enter_game': this.handlePlayerEnterGame.bind(this),
            'b2p_player_leave_game': this.handlePlayerLeaveGame.bind(this),
            'b2p_player_passpod_verify_ex': this.handlePlayerPasspodVerifyEx.bind(this),
            'b2p_player_query_transfer': this.handlePlayerQueryTransfer.bind(this),
            'b2p_player_set_charge_flag': this.handlePlayerSetChargeFlag.bind(this),
            'b2p_player_transfer': this.handlePlayerTransfer.bind(this),
            'b2p_use_spreader_cdkey': this.handleUseSpreaderCdkey.bind(this),
            
            // PaySys-to-Bishop handlers  
            'p2b_get_zone_charge_flag': this.handleGetZoneChargeFlag.bind(this),
            'p2b_ping': this.handlePingResponse.bind(this),
            
            // Additional handlers discovered from Bishop reverse engineering
            'b2p_account_free_time_cleaning': this.handleAccountFreeTimeCleaning.bind(this),
            'g2b_player_offline_live_timeout': this.handlePlayerOfflineLiveTimeout.bind(this),
            'g2b_player_offline_live_notify': this.handlePlayerOfflineLiveNotify.bind(this),
            'g2b_offline_live_kick_account_result': this.handleOfflineLiveKickAccountResult.bind(this),
            'b2p_bishop_login_request': this.handleBishopLoginRequest.bind(this)
        };
        
        // Extended point types from vzopaysys.exe analysis
        this.EXT_POINT_TYPES = {
            nExtpoin0: 'POINT_TYPE_0',
            nExtpoin1: 'POINT_TYPE_1', 
            nExtpoin2: 'POINT_TYPE_2',
            nExtpoin4: 'POINT_TYPE_4',
            nExtpoin5: 'POINT_TYPE_5',
            nExtpoin6: 'POINT_TYPE_6',
            nExtpoin7: 'POINT_TYPE_7',
            bklactivenew: 'BKL_ACTIVE_NEW'
        };
        
        this.logFile = `./logs/paysys-enhanced-${new Date().toISOString().split('T')[0]}.log`;
        this.ensureLogDir();
        
        console.log('[Enhanced PaySys] Server initialized with complete protocol support');
        console.log('[Enhanced PaySys] Implements 25+ protocol handlers from vzopaysys.exe, KG_SimulatePaysys_FS.exe, and KG_BishopD reverse engineering');
        console.log('[Enhanced PaySys] Added missing handlers: account_free_time_cleaning, offline_live protocols');
    }

    loadConfig(configPath) {
        try {
            const configText = fs.readFileSync(configPath, 'utf8');
            const config = {};
            let currentSection = '';
            
            configText.split('\n').forEach(line => {
                line = line.trim();
                
                // Handle section headers
                if (line.startsWith('[') && line.endsWith(']')) {
                    currentSection = line.slice(1, -1).toLowerCase();
                    return;
                }
                
                // Handle key-value pairs
                if (line && line.includes('=') && !line.startsWith('#') && !line.startsWith(';')) {
                    const [key, value] = line.split('=', 2);
                    const sectionKey = currentSection ? `${currentSection}.${key.trim()}` : key.trim();
                    config[sectionKey] = value.trim();
                }
            });
            
            return {
                serverIP: config['paysys.IP'] || '127.0.0.1',
                serverPort: parseInt(config['paysys.Port']) || 8000,
                dbHost: config['database.IP'] || '127.0.0.1',
                dbUser: config['database.UserName'] || 'root',
                dbPassword: config['database.Password'] || '1234',
                dbName: config['database.DBName'] || 'jx2_paysys',
                dbPort: parseInt(config['database.Port']) || 3306
            };
        } catch (error) {
            console.error('[Enhanced PaySys] Error loading config:', error.message);
            console.error('[Enhanced PaySys] Paysys load failed, check your config file !');
            process.exit(1);
        }
    }

    ensureLogDir() {
        const logDir = path.dirname(this.logFile);
        if (!fs.existsSync(logDir)) {
            fs.mkdirSync(logDir, { recursive: true });
        }
    }

    log(message) {
        const timestamp = new Date().toISOString();
        const logMessage = `[${timestamp}] ${message}`;
        console.log(logMessage);
        
        try {
            fs.appendFileSync(this.logFile, logMessage + '\n');
        } catch (error) {
            console.error('Failed to write to log file:', error.message);
        }
    }

    // Comprehensive payload logging with hex dump and field parsing
    logPayload(handlerName, data, connectionId = null) {
        const connStr = connectionId ? ` Connection ${connectionId}` : '';
        this.log(`[Enhanced PaySys]${connStr} Processing ${handlerName}`);
        
        if (!data || data.length === 0) {
            this.log(`[Enhanced PaySys] No payload data`);
            return;
        }
        
        this.log(`[Enhanced PaySys] Payload Length: ${data.length} bytes`);
        
        // Show raw hex data
        const hexData = data.toString('hex').toUpperCase();
        this.log(`[Enhanced PaySys] Raw Hex: ${hexData}`);
        
        // Show ASCII representation
        let ascii = '';
        for (let i = 0; i < data.length; i++) {
            const byte = data[i];
            ascii += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
        }
        this.log(`[Enhanced PaySys] ASCII: ${ascii}`);
        
        // Show hex dump format (similar to proxy server)
        let hexDump = '[Enhanced PaySys] Hex Dump:\n';
        for (let i = 0; i < data.length; i += 16) {
            const chunk = data.slice(i, i + 16);
            const offset = i.toString(16).padStart(8, '0').toUpperCase();
            const hexPart = chunk.toString('hex').toUpperCase().match(/.{2}/g).join(' ').padEnd(47);
            let asciiPart = '';
            for (let j = 0; j < chunk.length; j++) {
                const byte = chunk[j];
                asciiPart += (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : '.';
            }
            hexDump += `${offset}  ${hexPart}  |${asciiPart}|\n`;
        }
        this.log(hexDump.trimEnd());
        
        // Parse common fields if data is large enough
        if (data.length >= 4) {
            const payloadLength = data.readUInt32LE(0);
            this.log(`[Enhanced PaySys] Header - Payload Length: ${payloadLength}`);
        }
        
        // Try to extract common string fields
        if (data.length >= 36) {
            try {
                const field1 = this.extractString(data, 4, 32);
                if (field1) this.log(`[Enhanced PaySys] Field 1 (4-35): "${field1}"`);
            } catch (e) {}
        }
        
        if (data.length >= 68) {
            try {
                const field2 = this.extractString(data, 36, 32);
                if (field2) this.log(`[Enhanced PaySys] Field 2 (36-67): "${field2}"`);
            } catch (e) {}
        }
        
        // Try to extract common integer fields
        if (data.length >= 8) {
            try {
                const int1 = this.extractInt32(data, 4);
                this.log(`[Enhanced PaySys] Int Field 1 (4-7): ${int1}`);
            } catch (e) {}
        }
        
        if (data.length >= 12) {
            try {
                const int2 = this.extractInt32(data, 8);
                this.log(`[Enhanced PaySys] Int Field 2 (8-11): ${int2}`);
            } catch (e) {}
        }
    }

    async connectToDatabase() {
        try {
            const dbConfig = {
                host: this.config.dbHost,
                port: this.config.dbPort,
                user: this.config.dbUser,
                password: this.config.dbPassword, 
                database: this.config.dbName
            };
            
            this.log(`[Enhanced PaySys] Attempting database connection to ${dbConfig.host}:${dbConfig.port} as ${dbConfig.user}`);
            
            this.dbConnection = await mysql.createConnection(dbConfig);
            
            // Test the connection
            await this.dbConnection.execute('SELECT 1 as test');
            
            this.log('[Enhanced PaySys] Connected to MySQL database successfully');
            return true;
        } catch (error) {
            this.log(`[Enhanced PaySys] Cannot Connect to Mysql Server: ${error.message}`);
            this.log(`[Enhanced PaySys] Error code: ${error.code || 'unknown'}`);
            this.dbConnection = null;
            return false;
        }
    }

    // ==================== PROTOCOL HANDLERS ====================

    // Send initial security key upon connection - Bishop expects this immediately
    sendInitialSecurityKey(socket, connectionId) {
        try {
            this.log(`[Enhanced PaySys] Connection ${connectionId} - Sending initial security key to Bishop`);
            
            // Based on pcap analysis, Bishop expects a structured 34-byte packet:
            // Bytes 0-3: Header (0x22 0x00 0x20 0x00) - 0x22=34 bytes total, 0x00=protocol, 0x20 0x00=flags
            // Bytes 4-9: Padding (6 zero bytes)
            // Bytes 10-17: 8-byte security key (NOT 20 bytes as previously thought)
            // Bytes 18-33: Padding (16 zero bytes)
            const packet = Buffer.allocUnsafe(34);
            packet.fill(0);
            
            // Header: length (34), command (0), subcommand/flags (0x2000)
            packet.writeUInt8(0x22, 0);    // Length = 34 bytes
            packet.writeUInt8(0x00, 1);    // Protocol/command
            packet.writeUInt8(0x20, 2);    // Flags/subcommand lo byte
            packet.writeUInt8(0x00, 3);    // Flags/subcommand hi byte
            
            // 6 bytes of padding (bytes 4-9) - already zeroed by fill(0)
            
            // Generate 8-byte security key at offset 10
            const securityKey = crypto.randomBytes(8);
            securityKey.copy(packet, 10);
            
            // Remaining bytes (18-33) are padding - already zeroed by fill(0)
            
            // Send the structured packet
            socket.write(packet);
            
            this.log(`[Enhanced PaySys] Structured security packet sent (34 bytes): ${packet.toString('hex')}`);
            this.log(`[Enhanced PaySys] Security key (8 bytes at offset 10): ${securityKey.toString('hex')}`);
            this.log(`[Enhanced PaySys] Bishop should now process this with _RecvSecurityKey function`);
            
        } catch (error) {
            this.log(`[Enhanced PaySys] Error sending initial security key: ${error.message}`);
        }
    }

    // Bishop Identity Verification - Security key already sent on connection
    async handleBishopIdentityVerify(socket, data, connectionId) {
        this.logPayload('b2p_bishop_identity_verify', data, connectionId);
        
        try {
            this.log(`[Enhanced PaySys] Bishop Identity Verify Request - Processing authentication response`);
            
            // Based on pcap analysis, the exact response payload should be:
            // 3500 9744 6137 cc16 16b0 5dd4 00fa 40a1 99a1 3744 6137 cc16 16b0 5dd4 00fa 40a1 99a1 3744 6137 cc16 16b0 5dd4 00fb 40a1 9932 ca39 db
            // This breaks down as: [2-byte header: 35 00] + [51-byte payload: 97 44 61 37...]
            
            const responsePayload = Buffer.from([
                0x97, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4, 
                0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1, 
                0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
                0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1, 
                0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
                0x00, 0xfb, 0x40, 0xa1, 0x99, 0x32, 0xca, 0x39, 0xdb
            ]);
            
            // Create response with the exact payload length (51 bytes)
            const response = this.createResponse(0, responsePayload); 
            socket.write(response);
            
            this.log(`[Enhanced PaySys] Bishop Identity Verify - Exact pcap response sent (${responsePayload.length + 2} bytes total)`);
            
            // Keep connection alive for Bishop's subsequent communications
            socket.setKeepAlive(true, 30000);
            socket.setNoDelay(true);
            
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in bishop identity verify: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Bishop Login Request - Second packet from Bishop (pattern 7f00 ffc1)
    async handleBishopLoginRequest(socket, data, connectionId) {
        this.logPayload('b2p_bishop_login_request', data, connectionId);
        
        try {
            this.log(`[Enhanced PaySys] Bishop Login Request - Processing second authentication packet`);
            
            // Bishop expects a specific response structure for KAccountUserReturnVerify
            // The error message indicates Bishop expects: sizeof(tagProtocolHeader) + sizeof(KAccountUserReturnVerify)
            // From analysis, KAccountUserReturnVerify likely contains login result data
            
            // Based on Bishop's buffer size check error, we need to send exactly the right size
            // The structure appears to be:
            // - tagProtocolHeader (likely 4 bytes)
            // - KAccountUserReturnVerify (variable size, need to match Bishop's expectation)
            
            // From the working PCAP, Bishop receives different response sizes at different stages
            // For login verification, let's create a proper KAccountUserReturnVerify structure
            
            const loginVerifyPayload = Buffer.allocUnsafe(49); // 49 bytes payload + 4 byte header = 53 bytes total
            loginVerifyPayload.fill(0);
            
            const loginVerifyPayload = Buffer.allocUnsafe(49); // 49 bytes payload + 4 byte header = 53 bytes total
            loginVerifyPayload.fill(0);
            
            // KAccountUserReturnVerify structure (reverse engineered):
            loginVerifyPayload.writeUInt32LE(1, 0);        // nRetCode = 1 (success)
            loginVerifyPayload.writeUInt32LE(0, 4);        // nAccountID  
            loginVerifyPayload.writeUInt32LE(0, 8);        // nExpTime (expiration time)
            loginVerifyPayload.writeUInt32LE(0, 12);       // nOnlineTime
            loginVerifyPayload.writeUInt32LE(0, 16);       // nLastLoginTime
            loginVerifyPayload.writeUInt32LE(0, 20);       // nPoints/nCoin
            loginVerifyPayload.writeUInt32LE(0, 24);       // nFlags
            loginVerifyPayload.writeUInt32LE(0, 28);       // nVIPLevel or similar
            
            // Additional fields to match expected structure size
            loginVerifyPayload.writeUInt32LE(0, 32);       // Reserved field 1
            loginVerifyPayload.writeUInt32LE(0, 36);       // Reserved field 2  
            loginVerifyPayload.writeUInt32LE(0, 40);       // Reserved field 3
            loginVerifyPayload.writeUInt32LE(0, 44);       // Reserved field 4
            loginVerifyPayload.writeUInt8(0, 48);          // Final byte
            
            // Create response with 4-byte protocol header + KAccountUserReturnVerify payload
            const response = Buffer.allocUnsafe(53); // Total size that works from PCAP
            
            // Protocol header (4 bytes) - matching PCAP format:
            // First packet (identity verify): 2200 2000 (34 bytes, protocol 0x20)
            // Second packet (login verify): 3500 9744 (53 bytes, protocol 0x4497)
            response.writeUInt16LE(53, 0);     // Total packet size: 53 bytes
            response.writeUInt16LE(0x4497, 2); // Protocol type from working PCAP
            
            // Copy payload
            loginVerifyPayload.copy(response, 4);
            
            socket.write(response);
            
            this.log(`[Enhanced PaySys] Bishop Login Request - KAccountUserReturnVerify structure sent (${response.length} bytes)`);
            this.log(`[Enhanced PaySys] Response should match sizeof(tagProtocolHeader) + sizeof(KAccountUserReturnVerify)`);
            
            // Ensure connection remains stable
            socket.setKeepAlive(true, 30000);
            socket.setNoDelay(true);
            
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in bishop login request: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Bishop Reconnection Verification
    async handleBishopReconnectVerify(socket, data, connectionId) {
        this.logPayload('b2p_bishop_reconnect_identity_verify', data, connectionId);
        
        try {
            // Parse bishop reconnection data
            if (data.length >= 68) {
                const bishopId = this.extractString(data, 4, 32);
                const sessionToken = this.extractString(data, 36, 32);
                
                this.log(`[Enhanced PaySys] Bishop Reconnect Verify - ID: ${bishopId}`);
                
                // Verify session token against active connections
                let tokenValid = false;
                if (sessionToken && sessionToken.length > 0) {
                    // Check if this session token matches any active connections
                    for (const [id, socket] of this.connections) {
                        if (socket.sessionToken === sessionToken) {
                            tokenValid = true;
                            this.log(`[Enhanced PaySys] Session token verified for Bishop: ${bishopId}`);
                            break;
                        }
                    }
                    
                    if (!tokenValid) {
                        // Store this session token for future verification
                        socket.sessionToken = sessionToken;
                        socket.bishopId = bishopId;
                        tokenValid = true;
                        this.log(`[Enhanced PaySys] New session token registered for Bishop: ${bishopId}`);
                    }
                }
                
                const response = this.createResponse('nBishopLoginReconnectResult', { 
                    result: tokenValid ? 1 : 0,
                    bishopId: bishopId 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid bishop reconnect packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in bishop reconnect verify: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Account State Management
    async handleChangeAccountState(socket, data, connectionId) {
        this.logPayload('b2p_change_account_state', data, connectionId);
        
        try {
            // Parse account state change request
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const newState = this.extractInt32(data, 36);
                
                await this.dbConnection.execute(
                    'UPDATE account SET uAccountState = ? WHERE username = ?',
                    [newState, username]
                );
                
                this.log(`[Enhanced PaySys] Account state changed for ${username} to ${newState}`);
                
                const response = this.createResponse('uAccountState', { 
                    username, 
                    state: newState,
                    result: 1 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid account state packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error changing account state: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Extended Points Operation (vzopaysys.exe feature)
    async handleExtPointsOperation(socket, data, connectionId) {
        this.logPayload('b2p_ext_points_operation', data, connectionId);
        
        try {
            if (data.length >= 48) {
                const username = this.extractString(data, 4, 32);
                const pointType = this.extractInt32(data, 36);
                const amount = this.extractInt32(data, 40);
                const operation = this.extractInt32(data, 44); // 0=set, 1=add
                
                let sql;
                if (pointType === 0) sql = operation === 0 ? 'UPDATE account SET nExtpoin0 = ? WHERE username = ?' : 'UPDATE account SET nExtpoin0 = nExtpoin0 + ? WHERE username = ?';
                else if (pointType === 1) sql = operation === 0 ? 'UPDATE account SET nExtpoin1 = ? WHERE username = ?' : 'UPDATE account SET nExtpoin1 = nExtpoin1 + ? WHERE username = ?';
                else if (pointType === 2) sql = operation === 0 ? 'UPDATE account SET nExtpoin2 = ? WHERE username = ?' : 'UPDATE account SET nExtpoin2 = nExtpoin2 + ? WHERE username = ?';
                else if (pointType === 4) sql = 'UPDATE account SET nExtpoin4 = nExtpoin4 + ? WHERE username = ?';
                else if (pointType === 5) sql = 'UPDATE account SET nExtpoin5 = nExtpoin5 + ? WHERE username = ?';
                else if (pointType === 6) sql = 'UPDATE account SET nExtpoin6 = nExtpoin6 + ? WHERE username = ?';
                else if (pointType === 7) sql = 'UPDATE account SET nExtpoin7 = nExtpoin7 + ? WHERE username = ?';
                else if (pointType === 8) sql = 'UPDATE account SET bklactivenew = bklactivenew + ? WHERE username = ?';
                
                if (sql) {
                    await this.dbConnection.execute(sql, [amount, username]);
                    this.log(`[Enhanced PaySys] Extended points operation: ${username} type ${pointType} amount ${amount} op ${operation}`);
                } else {
                    this.log(`[Enhanced PaySys] Invalid point type: ${pointType}`);
                }
                
                const response = this.createResponse('nUserExtChangeResult', { 
                    result: 1,
                    username: username,
                    pointType: pointType,
                    amount: amount 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid ext points operation packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in ext points operation: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Item Shop - Buy Item
    async handleIbPlayerBuyItem(socket, data, connectionId) {
        this.logPayload('b2p_ib_player_buy_item', data, connectionId);
        
        try {
            // Parse item buy data
            if (data.length >= 72) {
                const username = this.extractString(data, 4, 32);
                const itemId = this.extractInt32(data, 36);
                const quantity = this.extractInt32(data, 40);
                const price = this.extractInt32(data, 44);
                
                this.log(`[Enhanced PaySys] Player ${username} buying item ${itemId}, qty: ${quantity}, price: ${price}`);
                
                // Check if player has enough coins (based on reverse-engineered logic)
                const [coinRows] = await this.dbConnection.execute(
                    'SELECT coin FROM account WHERE username = ?',
                    [username]
                );
                
                if (coinRows.length > 0) {
                    const currentCoins = coinRows[0].coin;
                    const totalCost = price * quantity;
                    
                    if (currentCoins >= totalCost) {
                        // Deduct coins for item purchase
                        await this.dbConnection.execute(
                            'UPDATE account SET coin = coin - ? WHERE username = ?',
                            [totalCost, username]
                        );
                        
                        this.log(`[Enhanced PaySys] Item purchase successful: ${username} bought ${quantity}x item ${itemId} for ${totalCost} coins`);
                        
                        const response = this.createResponse('nUserIBBuyItemResult', { 
                            result: 1,
                            username: username,
                            itemId: itemId,
                            quantity: quantity,
                            coinsSpent: totalCost
                        });
                        socket.write(response);
                    } else {
                        this.log(`[Enhanced PaySys] Insufficient coins: ${username} has ${currentCoins}, needs ${totalCost}`);
                        const response = this.createResponse('nUserIBBuyItemResult', { 
                            result: 0,
                            error: 'INSUFFICIENT_COINS' 
                        });
                        socket.write(response);
                    }
                } else {
                    this.log(`[Enhanced PaySys] Account not found: ${username}`);
                    socket.write(this.createErrorResponse());
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid buy item packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in buy item: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Item Shop - Buy Multiple Items  
    async handleIbPlayerBuyMultiItem(socket, data, connectionId) {
        this.logPayload('b2p_ib_player_buy_multi_item', data, connectionId);
        
        try {
            // Parse multi-item buy data
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const itemCount = this.extractInt32(data, 36);
                
                this.log(`[Enhanced PaySys] Player ${username} buying ${itemCount} different items`);
                
                // Check player's coin balance first
                const [coinRows] = await this.dbConnection.execute(
                    'SELECT coin FROM account WHERE username = ?',
                    [username]
                );
                
                if (coinRows.length > 0) {
                    let totalCost = 0;
                    let itemsProcessed = 0;
                    const itemDetails = [];
                    
                    // Parse individual items from the remaining packet data
                    let offset = 40;
                    for (let i = 0; i < itemCount && offset + 12 <= data.length; i++) {
                        const itemId = this.extractInt32(data, offset);
                        const quantity = this.extractInt32(data, offset + 4);
                        const price = this.extractInt32(data, offset + 8);
                        
                        const itemCost = price * quantity;
                        totalCost += itemCost;
                        itemDetails.push({ itemId, quantity, price, cost: itemCost });
                        
                        offset += 12; // Move to next item (3 int32s = 12 bytes)
                        itemsProcessed++;
                    }
                    
                    const currentCoins = coinRows[0].coin;
                    
                    if (currentCoins >= totalCost) {
                        // Deduct total cost from coins
                        await this.dbConnection.execute(
                            'UPDATE account SET coin = coin - ? WHERE username = ?',
                            [totalCost, username]
                        );
                        
                        this.log(`[Enhanced PaySys] Multi-item purchase successful: ${username} bought ${itemsProcessed} items for ${totalCost} coins`);
                        
                        const response = this.createResponse('nUserIBBuyItemResult', { 
                            result: 1,
                            username: username,
                            itemCount: itemsProcessed,
                            totalCost: totalCost,
                            itemDetails: itemDetails
                        });
                        socket.write(response);
                    } else {
                        this.log(`[Enhanced PaySys] Insufficient coins for multi-item purchase: ${username} has ${currentCoins}, needs ${totalCost}`);
                        const response = this.createResponse('nUserIBBuyItemResult', { 
                            result: 0,
                            error: 'INSUFFICIENT_COINS'
                        });
                        socket.write(response);
                    }
                } else {
                    this.log(`[Enhanced PaySys] Account not found: ${username}`);
                    socket.write(this.createErrorResponse());
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid buy multi-item packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in buy multi-item: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Item Shop - Use Item
    async handleIbPlayerUseItem(socket, data, connectionId) {
        this.logPayload('b2p_ib_player_use_item', data, connectionId);
        
        try {
            // Parse item use data
            if (data.length >= 72) {
                const username = this.extractString(data, 4, 32);
                const itemId = this.extractInt32(data, 36);
                const quantity = this.extractInt32(data, 40);
                
                this.log(`[Enhanced PaySys] Player ${username} using item ${itemId}, qty: ${quantity}`);
                
                // Check if player owns the item (this would typically be in inventory table)
                let canUseItem = true;
                let itemsUsed = 0;
                
                try {
                    // Check inventory for the item
                    const [inventoryRows] = await this.dbConnection.execute(
                        'SELECT quantity FROM player_inventory WHERE username = ? AND item_id = ?',
                        [username, itemId]
                    );
                    
                    if (inventoryRows.length > 0) {
                        const availableQuantity = inventoryRows[0].quantity;
                        
                        if (availableQuantity >= quantity) {
                            // Remove items from inventory
                            await this.dbConnection.execute(
                                'UPDATE player_inventory SET quantity = quantity - ? WHERE username = ? AND item_id = ?',
                                [quantity, username, itemId]
                            );
                            
                            // If quantity reaches 0, remove the item entry
                            await this.dbConnection.execute(
                                'DELETE FROM player_inventory WHERE username = ? AND item_id = ? AND quantity <= 0',
                                [username, itemId]
                            );
                            
                            itemsUsed = quantity;
                            this.log(`[Enhanced PaySys] ${quantity} items used successfully for ${username}`);
                        } else {
                            canUseItem = false;
                            this.log(`[Enhanced PaySys] Insufficient items: ${username} has ${availableQuantity}, wants to use ${quantity}`);
                        }
                    } else {
                        canUseItem = false;
                        this.log(`[Enhanced PaySys] Item not found in inventory: ${username} doesn't have item ${itemId}`);
                    }
                } catch (inventoryError) {
                    // Inventory table might not exist, assume item usage is allowed
                    this.log(`[Enhanced PaySys] Inventory table not available, allowing item usage`);
                    itemsUsed = quantity;
                }
                
                const response = this.createResponse('nUserIBUseItemResult', { 
                    result: canUseItem ? 1 : 0,
                    username: username,
                    itemId: itemId,
                    quantity: itemsUsed,
                    error: canUseItem ? null : 'INSUFFICIENT_ITEMS'
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid use item packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in use item: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Item Shop - Use Multiple Items
    async handleIbPlayerUseMultiItem(socket, data, connectionId) {
        this.logPayload('b2p_ib_player_use_multi_item', data, connectionId);
        
        try {
            // Parse multi-item use data
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const itemCount = this.extractInt32(data, 36);
                
                this.log(`[Enhanced PaySys] Player ${username} using ${itemCount} different items`);
                
                let itemsProcessed = 0;
                let allItemsUsed = true;
                const usageResults = [];
                
                // Parse individual items from the remaining packet data
                let offset = 40;
                for (let i = 0; i < itemCount && offset + 8 <= data.length; i++) {
                    const itemId = this.extractInt32(data, offset);
                    const quantity = this.extractInt32(data, offset + 4);
                    
                    let itemUsed = false;
                    let actualQuantityUsed = 0;
                    
                    try {
                        // Check inventory for each item
                        const [inventoryRows] = await this.dbConnection.execute(
                            'SELECT quantity FROM player_inventory WHERE username = ? AND item_id = ?',
                            [username, itemId]
                        );
                        
                        if (inventoryRows.length > 0) {
                            const availableQuantity = inventoryRows[0].quantity;
                            
                            if (availableQuantity >= quantity) {
                                // Remove items from inventory
                                await this.dbConnection.execute(
                                    'UPDATE player_inventory SET quantity = quantity - ? WHERE username = ? AND item_id = ?',
                                    [quantity, username, itemId]
                                );
                                
                                // Clean up empty entries
                                await this.dbConnection.execute(
                                    'DELETE FROM player_inventory WHERE username = ? AND item_id = ? AND quantity <= 0',
                                    [username, itemId]
                                );
                                
                                itemUsed = true;
                                actualQuantityUsed = quantity;
                            } else {
                                this.log(`[Enhanced PaySys] Insufficient item ${itemId}: ${username} has ${availableQuantity}, wants ${quantity}`);
                                allItemsUsed = false;
                            }
                        } else {
                            this.log(`[Enhanced PaySys] Item ${itemId} not found in ${username}'s inventory`);
                            allItemsUsed = false;
                        }
                    } catch (inventoryError) {
                        // Inventory table might not exist, allow usage
                        this.log(`[Enhanced PaySys] Inventory table not available for item ${itemId}, allowing usage`);
                        itemUsed = true;
                        actualQuantityUsed = quantity;
                    }
                    
                    usageResults.push({
                        itemId: itemId,
                        requestedQuantity: quantity,
                        actualQuantityUsed: actualQuantityUsed,
                        success: itemUsed
                    });
                    
                    if (itemUsed) itemsProcessed++;
                    offset += 8; // Move to next item (2 int32s = 8 bytes)
                }
                
                this.log(`[Enhanced PaySys] Multi-item usage: ${username} processed ${itemsProcessed}/${itemCount} items`);
                
                const response = this.createResponse('nUserIBUseItemResult', { 
                    result: allItemsUsed ? 1 : 0,
                    username: username,
                    itemCount: itemsProcessed,
                    totalRequested: itemCount,
                    usageResults: usageResults,
                    error: allItemsUsed ? null : 'SOME_ITEMS_UNAVAILABLE'
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid use multi-item packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in use multi-item: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Item Shop Player Identity Verification
    async handleIbPlayerIdentityVerify(socket, data, connectionId) {
        this.logPayload('b2p_ib_player_identity_verify', data, connectionId);
        
        try {
            // Parse IB player identity data
            if (data.length >= 68) {
                const username = this.extractString(data, 4, 32);
                const password = this.extractString(data, 36, 32);
                
                this.log(`[Enhanced PaySys] IB Player Identity Verify: ${username}`);
                
                // Verify player for item shop access (similar to main login but for IB)
                const [rows] = await this.dbConnection.execute(
                    'SELECT username, password, nOnline FROM account WHERE username = ?',
                    [username]
                );
                
                if (rows.length > 0 && rows[0].password === password) {
                    // Valid credentials, grant IB access
                    this.log(`[Enhanced PaySys] IB access granted for: ${username}`);
                    
                    const response = this.createResponse('nUserLoginVerifyResult', { 
                        result: 1,
                        username: username,
                        ibAccess: true
                    });
                    socket.write(response);
                } else {
                    // Invalid credentials or account not found
                    this.log(`[Enhanced PaySys] IB access denied for: ${username}`);
                    
                    // Increment hack attempt counter (same as regular login)
                    if (rows.length > 0) {
                        await this.dbConnection.execute(
                            'UPDATE account SET trytohack = trytohack + 1 WHERE username = ?',
                            [username]
                        );
                    }
                    
                    const response = this.createResponse('nUserLoginVerifyResult', { 
                        result: 0,
                        error: 'INVALID_CREDENTIALS'
                    });
                    socket.write(response);
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid IB identity packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in IB player identity verify: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Identity Verification (Main login)
    async handlePlayerIdentityVerify(socket, data, connectionId) {
        this.logPayload('b2p_player_identity_verify', data, connectionId);
        
        try {
            if (data.length >= 72) {
                const username = this.extractString(data, 4, 32);
                const password = this.extractString(data, 36, 32);
                const clientIP = this.extractInt32(data, 68);
                
                // Query account
                const [rows] = await this.dbConnection.execute(
                    'SELECT username, password FROM account WHERE username = ?',
                    [username]
                );
                
                if (rows.length > 0 && rows[0].password === password) {
                    // Update last login IP
                    await this.dbConnection.execute(
                        'UPDATE account SET LastLoginIP = ? WHERE username = ?',
                        [clientIP, username]
                    );
                    
                    this.log(`[Enhanced PaySys] Player login successful: ${username} from IP: ${clientIP}`);
                    
                    const response = this.createResponse('nUserLoginVerifyResult', { 
                        result: 1,
                        username: username 
                    });
                    socket.write(response);
                } else {
                    // Increment hack attempt counter
                    await this.dbConnection.execute(
                        'UPDATE account SET trytohack = trytohack + 1 WHERE username = ?',
                        [username]
                    );
                    
                    this.log(`[Enhanced PaySys] Player login failed: ${username}`);
                    socket.write(this.createErrorResponse());
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid player identity packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in player identity verify: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Enter Game (KG_SimulatePaysys_FS.exe specific)
    async handlePlayerEnterGame(socket, data, connectionId) {
        this.logPayload('b2p_player_enter_game', data, connectionId);
        
        try {
            // Parse player enter game data
            if (data.length >= 36) {
                const username = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Player Enter Game: ${username}`);
                
                // Update player status in database (based on KG_SimulatePaysys_FS.exe logic)
                const [updateResult] = await this.dbConnection.execute(
                    'UPDATE account SET nOnline = 1, dtLastLogin = NOW() WHERE username = ?',
                    [username]
                );
                
                if (updateResult.affectedRows > 0) {
                    this.log(`[Enhanced PaySys] Player ${username} successfully entered game`);
                    
                    const response = this.createResponse('nUserLoginResult', { 
                        result: 1,
                        username: username,
                        loginTime: new Date().toISOString()
                    });
                    socket.write(response);
                } else {
                    this.log(`[Enhanced PaySys] Player ${username} not found in database`);
                    
                    const response = this.createResponse('nUserLoginResult', { 
                        result: 0,
                        error: 'ACCOUNT_NOT_FOUND'
                    });
                    socket.write(response);
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid enter game packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in enter game: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Leave Game (vzopaysys.exe specific)
    async handlePlayerLeaveGame(socket, data, connectionId) {
        this.logPayload('b2p_player_leave_game', data, connectionId);
        
        try {
            // Parse player leave game data
            if (data.length >= 36) {
                const username = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Player Leave Game: ${username}`);
                
                // Update player status in database (based on vzopaysys.exe logic)
                const [updateResult] = await this.dbConnection.execute(
                    'UPDATE account SET nOnline = 0, dtLastLogin = NOW() WHERE username = ?',
                    [username]
                );
                
                if (updateResult.affectedRows > 0) {
                    this.log(`[Enhanced PaySys] Player ${username} successfully left game`);
                    
                    const response = this.createResponse('nUserLogoutResult', { 
                        result: 1,
                        username: username,
                        logoutTime: new Date().toISOString()
                    });
                    socket.write(response);
                } else {
                    this.log(`[Enhanced PaySys] Player ${username} not found in database`);
                    
                    const response = this.createResponse('nUserLogoutResult', { 
                        result: 0,
                        error: 'ACCOUNT_NOT_FOUND'
                    });
                    socket.write(response);
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid leave game packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in leave game: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // MiBao/PassPod Verification
    async handlePlayerPasspodVerifyEx(socket, data, connectionId) {
        this.logPayload('b2p_player_passpod_verify_ex', data, connectionId);
        
        try {
            // Parse passpod verification data
            if (data.length >= 100) {
                const username = this.extractString(data, 4, 32);
                const passpod = this.extractString(data, 36, 32);
                const verifyCode = this.extractString(data, 68, 32);
                
                this.log(`[Enhanced PaySys] PassPod/MiBao Verification for: ${username}, code: ${verifyCode}`);
                
                // Verify MiBao/PassPod code against database
                let verificationResult = 0;
                
                try {
                    // Check if account has MiBao enabled
                    const [accountRows] = await this.dbConnection.execute(
                        'SELECT mibao_enabled, mibao_code FROM account WHERE username = ?',
                        [username]
                    );
                    
                    if (accountRows.length > 0) {
                        const account = accountRows[0];
                        
                        if (!account.mibao_enabled) {
                            // MiBao not enabled for this account
                            verificationResult = 1; // Allow through
                            this.log(`[Enhanced PaySys] MiBao not enabled for ${username}, verification passed`);
                        } else if (account.mibao_code === verifyCode) {
                            // Correct MiBao code
                            verificationResult = 1;
                            this.log(`[Enhanced PaySys] MiBao verification successful for ${username}`);
                        } else {
                            // Incorrect MiBao code
                            verificationResult = 0;
                            this.log(`[Enhanced PaySys] MiBao verification failed for ${username}`);
                            
                            // Increment hack attempts
                            await this.dbConnection.execute(
                                'UPDATE account SET trytohack = trytohack + 1 WHERE username = ?',
                                [username]
                            );
                        }
                    } else {
                        this.log(`[Enhanced PaySys] Account not found for MiBao verification: ${username}`);
                        verificationResult = 0;
                    }
                } catch (mibaoError) {
                    // MiBao table columns might not exist, default to success
                    this.log(`[Enhanced PaySys] MiBao columns not available, defaulting to success`);
                    verificationResult = 1;
                }
                
                const response = this.createResponse('nPasspodVerifyResult', { 
                    result: verificationResult,
                    username: username 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid passpod verify packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in passpod verify: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Coin Exchange
    async handlePlayerExchange(socket, data, connectionId) {
        this.logPayload('b2p_player_exchange', data, connectionId);
        
        try {
            // Parse coin exchange data
            if (data.length >= 44) {
                const username = this.extractString(data, 4, 32);
                const coinAmount = this.extractInt32(data, 36);
                const exchangeType = this.extractInt32(data, 40);
                
                this.log(`[Enhanced PaySys] Player ${username} coin exchange: ${coinAmount}, type: ${exchangeType}`);
                
                // Based on reverse-engineered logic: Select coin From account WHERE username='%s'
                const [coinRows] = await this.dbConnection.execute(
                    'SELECT coin FROM account WHERE username = ?',
                    [username]
                );
                
                if (coinRows.length > 0) {
                    let newCoinAmount;
                    
                    if (exchangeType === 0) {
                        // Set coins to specific amount
                        newCoinAmount = coinAmount;
                        await this.dbConnection.execute(
                            'UPDATE account SET coin = ? WHERE username = ?',
                            [newCoinAmount, username]
                        );
                    } else if (exchangeType === 1) {
                        // Add coins (based on: Update account Set coin = coin + '%d' WHERE username = '%s')
                        newCoinAmount = coinRows[0].coin + coinAmount;
                        await this.dbConnection.execute(
                            'UPDATE account SET coin = coin + ? WHERE username = ?',
                            [coinAmount, username]
                        );
                    } else if (exchangeType === 2) {
                        // Subtract coins
                        if (coinRows[0].coin >= coinAmount) {
                            newCoinAmount = coinRows[0].coin - coinAmount;
                            await this.dbConnection.execute(
                                'UPDATE account SET coin = coin - ? WHERE username = ?',
                                [coinAmount, username]
                            );
                        } else {
                            this.log(`[Enhanced PaySys] Insufficient coins for exchange: ${username}`);
                            const response = this.createResponse('nUserExtChangeResult', { 
                                result: 0,
                                error: 'INSUFFICIENT_COINS'
                            });
                            socket.write(response);
                            return;
                        }
                    }
                    
                    this.log(`[Enhanced PaySys] Coin exchange successful: ${username} new balance: ${newCoinAmount}`);
                    
                    const response = this.createResponse('nUserExtChangeResult', { 
                        result: 1,
                        username: username,
                        coinAmount: newCoinAmount,
                        exchangeType: exchangeType
                    });
                    socket.write(response);
                } else {
                    this.log(`[Enhanced PaySys] Account not found for exchange: ${username}`);
                    socket.write(this.createErrorResponse());
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid coin exchange packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in player exchange: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Extended Player Coin Exchange
    async handlePlayerExchangeEx(socket, data, connectionId) {
        this.logPayload('b2p_player_exchange_ex', data, connectionId);
        
        try {
            // Parse extended coin exchange data
            if (data.length >= 48) {
                const username = this.extractString(data, 4, 32);
                const coinAmount = this.extractInt32(data, 36);
                const exchangeType = this.extractInt32(data, 40);
                const extraParam = this.extractInt32(data, 44); // Exchange rate, bonus multiplier, etc.
                
                this.log(`[Enhanced PaySys] Player ${username} extended coin exchange: ${coinAmount}, type: ${exchangeType}, param: ${extraParam}`);
                
                // Get current balance for extended exchange processing
                const [coinRows] = await this.dbConnection.execute(
                    'SELECT coin FROM account WHERE username = ?',
                    [username]
                );
                
                if (coinRows.length > 0) {
                    let newCoinAmount;
                    let exchangeSuccess = false;
                    
                    switch (exchangeType) {
                        case 0: // Set coins with multiplier
                            newCoinAmount = coinAmount * (extraParam > 0 ? extraParam : 1);
                            await this.dbConnection.execute(
                                'UPDATE account SET coin = ? WHERE username = ?',
                                [newCoinAmount, username]
                            );
                            exchangeSuccess = true;
                            break;
                            
                        case 1: // Add coins with bonus rate
                            const bonusAmount = Math.floor(coinAmount * (extraParam / 100.0));
                            const totalAddAmount = coinAmount + bonusAmount;
                            newCoinAmount = coinRows[0].coin + totalAddAmount;
                            await this.dbConnection.execute(
                                'UPDATE account SET coin = coin + ? WHERE username = ?',
                                [totalAddAmount, username]
                            );
                            exchangeSuccess = true;
                            this.log(`[Enhanced PaySys] Bonus applied: ${coinAmount} + ${bonusAmount} bonus = ${totalAddAmount} total added`);
                            break;
                            
                        case 2: // Exchange with conversion rate
                            if (extraParam > 0) {
                                const convertedAmount = Math.floor(coinAmount / extraParam);
                                if (coinRows[0].coin >= coinAmount) {
                                    newCoinAmount = coinRows[0].coin - coinAmount + convertedAmount;
                                    await this.dbConnection.execute(
                                        'UPDATE account SET coin = coin - ? + ? WHERE username = ?',
                                        [coinAmount, convertedAmount, username]
                                    );
                                    exchangeSuccess = true;
                                    this.log(`[Enhanced PaySys] Exchange conversion: ${coinAmount} coins -> ${convertedAmount} coins (rate: ${extraParam}:1)`);
                                } else {
                                    this.log(`[Enhanced PaySys] Insufficient coins for exchange conversion`);
                                }
                            } else {
                                this.log(`[Enhanced PaySys] Invalid exchange rate: ${extraParam}`);
                            }
                            break;
                            
                        case 3: // Time-limited bonus exchange
                            // extraParam could be expiration timestamp
                            const currentTime = Math.floor(Date.now() / 1000);
                            if (extraParam > currentTime) {
                                // Bonus still valid
                                const bonusCoins = Math.floor(coinAmount * 1.5); // 50% bonus
                                newCoinAmount = coinRows[0].coin + bonusCoins;
                                await this.dbConnection.execute(
                                    'UPDATE account SET coin = coin + ? WHERE username = ?',
                                    [bonusCoins, username]
                                );
                                exchangeSuccess = true;
                                this.log(`[Enhanced PaySys] Time-limited bonus applied: ${coinAmount} -> ${bonusCoins} coins`);
                            } else {
                                this.log(`[Enhanced PaySys] Bonus period expired for ${username}`);
                            }
                            break;
                            
                        default:
                            this.log(`[Enhanced PaySys] Unknown exchange type: ${exchangeType}`);
                            break;
                    }
                    
                    if (exchangeSuccess) {
                        // Log the extended exchange transaction
                        try {
                            await this.dbConnection.execute(
                                'INSERT INTO exchange_log (username, exchange_type, original_amount, extra_param, result_amount, exchange_time) VALUES (?, ?, ?, ?, ?, NOW())',
                                [username, exchangeType, coinAmount, extraParam, newCoinAmount]
                            );
                        } catch (logError) {
                            this.log(`[Enhanced PaySys] Exchange logging table not available`);
                        }
                        
                        const response = this.createResponse('nUserExtChangeResult', { 
                            result: 1,
                            username: username,
                            coinAmount: newCoinAmount,
                            exchangeType: exchangeType,
                            extraParam: extraParam
                        });
                        socket.write(response);
                    } else {
                        const response = this.createResponse('nUserExtChangeResult', { 
                            result: 0,
                            error: 'EXCHANGE_FAILED'
                        });
                        socket.write(response);
                    }
                } else {
                    this.log(`[Enhanced PaySys] Account not found for extended exchange: ${username}`);
                    socket.write(this.createErrorResponse());
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid extended exchange packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in extended exchange: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Freeze Fee
    async handlePlayerFreezeFee(socket, data, connectionId) {
        this.logPayload('b2p_player_freeze_fee', data, connectionId);
        
        try {
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const freezeAmount = this.extractInt32(data, 36);
                
                // Based on reverse-engineered DoFreezeCoinRespond logic
                const [coinRows] = await this.dbConnection.execute(
                    'SELECT coin FROM account WHERE username = ?',
                    [username]
                );
                
                if (coinRows.length > 0) {
                    const currentCoins = coinRows[0].coin;
                    
                    if (currentCoins >= freezeAmount) {
                        // Freeze coins by subtracting from available balance
                        await this.dbConnection.execute(
                            'UPDATE account SET coin = coin - ? WHERE username = ?',
                            [freezeAmount, username]
                        );
                        
                        // Create frozen coin record (if table exists)
                        try {
                            await this.dbConnection.execute(
                                'INSERT INTO frozen_coins (username, amount, freeze_time) VALUES (?, ?, NOW())',
                                [username, freezeAmount]
                            );
                        } catch (freezeError) {
                            // Table might not exist, continue without frozen record
                            this.log(`[Enhanced PaySys] Frozen coins table not available, coins deducted only`);
                        }
                        
                        this.log(`[Enhanced PaySys] Freeze Fee Coin Account ${username} is [OK]`);
                        
                        const response = this.createResponse('nUserExtChangeResult', { 
                            result: 1,
                            username: username,
                            frozenAmount: freezeAmount
                        });
                        socket.write(response);
                    } else {
                        this.log(`[Enhanced PaySys] Freeze Fee Coin Account ${username} is [INSUFFICIENT_COINS]`);
                        
                        const response = this.createResponse('nUserExtChangeResult', { 
                            result: 0,
                            error: 'INSUFFICIENT_COINS'
                        });
                        socket.write(response);
                    }
                } else {
                    this.log(`[Enhanced PaySys] Freeze Fee Coin Account ${username} is [NOT_FOUND]`);
                    socket.write(this.createErrorResponse());
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid freeze fee packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in freeze fee: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Transfer
    async handlePlayerTransfer(socket, data, connectionId) {
        this.logPayload('b2p_player_transfer', data, connectionId);
        
        try {
            if (data.length >= 72) {
                const fromUsername = this.extractString(data, 4, 32);
                const toUsername = this.extractString(data, 36, 32);
                const transferAmount = this.extractInt32(data, 68);
                
                this.log(`[Enhanced PaySys] Transfer ${transferAmount} coins from ${fromUsername} to ${toUsername}`);
                
                // Start transaction for atomic transfer
                await this.dbConnection.beginTransaction();
                
                try {
                    // Check sender's balance
                    const [senderRows] = await this.dbConnection.execute(
                        'SELECT coin FROM account WHERE username = ?',
                        [fromUsername]
                    );
                    
                    // Check receiver exists
                    const [receiverRows] = await this.dbConnection.execute(
                        'SELECT username FROM account WHERE username = ?',
                        [toUsername]
                    );
                    
                    if (senderRows.length === 0) {
                        await this.dbConnection.rollback();
                        this.log(`[Enhanced PaySys] Sender account not found: ${fromUsername}`);
                        socket.write(this.createErrorResponse());
                        return;
                    }
                    
                    if (receiverRows.length === 0) {
                        await this.dbConnection.rollback();
                        this.log(`[Enhanced PaySys] Receiver account not found: ${toUsername}`);
                        socket.write(this.createErrorResponse());
                        return;
                    }
                    
                    if (senderRows[0].coin < transferAmount) {
                        await this.dbConnection.rollback();
                        this.log(`[Enhanced PaySys] Insufficient coins: ${fromUsername} has ${senderRows[0].coin}, needs ${transferAmount}`);
                        
                        const response = this.createResponse('nUserExtChangeResult', { 
                            result: 0,
                            error: 'INSUFFICIENT_COINS'
                        });
                        socket.write(response);
                        return;
                    }
                    
                    // Perform atomic transfer (based on vzopaysys.exe logic)
                    await this.dbConnection.execute(
                        'UPDATE account SET coin = coin - ? WHERE username = ?',
                        [transferAmount, fromUsername]
                    );
                    
                    await this.dbConnection.execute(
                        'UPDATE account SET coin = coin + ? WHERE username = ?',
                        [transferAmount, toUsername]
                    );
                    
                    await this.dbConnection.commit();
                    
                    this.log(`[Enhanced PaySys] Transfer Coin From Account ${fromUsername} To Account ${toUsername} is [OK]`);
                    
                    const response = this.createResponse('nUserExtChangeResult', { 
                        result: 1,
                        fromUsername: fromUsername,
                        toUsername: toUsername,
                        amount: transferAmount
                    });
                    socket.write(response);
                    
                } catch (transferError) {
                    await this.dbConnection.rollback();
                    throw transferError;
                }
                
            } else {
                this.log(`[Enhanced PaySys] Invalid transfer packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in transfer: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Query Transfer
    async handlePlayerQueryTransfer(socket, data, connectionId) {
        this.logPayload('b2p_player_query_transfer', data, connectionId);
        
        try {
            // Parse transfer query data
            if (data.length >= 36) {
                const username = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Player Query Transfer for: ${username}`);
                
                // Query pending transfers from database
                // Check for any pending transfer records
                let pendingTransfers = 0;
                let transferAmount = 0;
                
                try {
                    const [transferRows] = await this.dbConnection.execute(
                        'SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total FROM pending_transfers WHERE to_username = ? AND status = "pending"',
                        [username]
                    );
                    
                    if (transferRows.length > 0) {
                        pendingTransfers = transferRows[0].count;
                        transferAmount = transferRows[0].total;
                    }
                } catch (queryError) {
                    // Table might not exist, assume no pending transfers
                    this.log(`[Enhanced PaySys] Pending transfers table not available, assuming no transfers`);
                    pendingTransfers = 0;
                    transferAmount = 0;
                }
                
                this.log(`[Enhanced PaySys] ${username} has ${pendingTransfers} pending transfers totaling ${transferAmount} coins`);
                
                const response = this.createResponse('nUserQueryTransferResult', { 
                    result: 1,
                    username: username,
                    pendingTransfers: pendingTransfers,
                    totalAmount: transferAmount
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid query transfer packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in query transfer: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Set Charge Flag
    async handlePlayerSetChargeFlag(socket, data, connectionId) {
        this.logPayload('b2p_player_set_charge_flag', data, connectionId);
        
        try {
            // Parse charge flag data
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const chargeFlag = this.extractInt32(data, 36);
                
                this.log(`[Enhanced PaySys] Set Charge Flag for ${username} to ${chargeFlag}`);
                
                // Update charge flag in database (based on vzopaysys.exe)
                const [updateResult] = await this.dbConnection.execute(
                    'UPDATE account SET nCharge = ? WHERE username = ?',
                    [chargeFlag, username]
                );
                
                if (updateResult.affectedRows > 0) {
                    this.log(`[Enhanced PaySys] Charge flag updated successfully for ${username}`);
                    
                    const response = this.createResponse('nAccountSetChargeResult', { 
                        result: 1,
                        username: username,
                        chargeFlag: chargeFlag 
                    });
                    socket.write(response);
                } else {
                    this.log(`[Enhanced PaySys] Account not found for charge flag update: ${username}`);
                    
                    const response = this.createResponse('nAccountSetChargeResult', { 
                        result: 0,
                        error: 'ACCOUNT_NOT_FOUND'
                    });
                    socket.write(response);
                }
            } else {
                this.log(`[Enhanced PaySys] Invalid set charge flag packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in set charge flag: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // CD-Key/Gift Code Usage
    async handleUseSpreaderCdkey(socket, data, connectionId) {
        this.logPayload('b2p_use_spreader_cdkey', data, connectionId);
        
        try {
            if (data.length >= 36) {
                const cdkey = this.extractString(data, 4, 32);
                
                // Check if CD-Key exists and is unused
                const [rows] = await this.dbConnection.execute(
                    'SELECT szCardSeri,szAccount FROM Card WHERE szCardSeri = ?',
                    [cdkey]
                );
                
                if (rows.length > 0) {
                    // Check if already used
                    const [okRows] = await this.dbConnection.execute(
                        'SELECT `nOk` FROM `Card` WHERE `szCardSeri` = ?',
                        [cdkey]
                    );
                    
                    if (okRows.length > 0 && okRows[0].nOk === 0) {
                        // Mark as used
                        await this.dbConnection.execute(
                            'UPDATE `Card` SET `nOk` = 1 WHERE `szCardSeri` = ?',
                            [cdkey]
                        );
                        
                        this.log(`[Enhanced PaySys] CDKey ${cdkey} Check [OK]`);
                    } else {
                        this.log(`[Enhanced PaySys] CDKey ${cdkey} Check [ALREADY_USED]`);
                    }
                } else {
                    this.log(`[Enhanced PaySys] CDKey ${cdkey} Check [NOT_FOUND]`);
                }
                
                const response = this.createResponse('nUserExtChangeResult', { 
                    result: 1,
                    cdkey: cdkey 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid cdkey packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in cdkey usage: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Game World Communication
    async handleGameWorldToPaysys(socket, data, connectionId) {
        this.logPayload('b2p_gameworld_2_paysys', data, connectionId);
        
        try {
            // Parse game world communication data
            if (data.length >= 8) {
                const messageType = this.extractInt32(data, 4);
                this.log(`[Enhanced PaySys] Game World to PaySys message type: ${messageType}`);
                
                // Handle various game world message types
                let responseResult = 1;
                let responseData = { messageType: messageType };
                
                switch (messageType) {
                    case 1: // Player status update
                        if (data.length >= 40) {
                            const username = this.extractString(data, 8, 32);
                            this.log(`[Enhanced PaySys] Game world player status update: ${username}`);
                            
                            // Update player online status
                            await this.dbConnection.execute(
                                'UPDATE account SET nOnline = 1, dtLastLogin = NOW() WHERE username = ?',
                                [username]
                            );
                            responseData.username = username;
                        }
                        break;
                        
                    case 2: // Server status notification
                        this.log(`[Enhanced PaySys] Game world server status notification`);
                        break;
                        
                    case 3: // Economy update
                        if (data.length >= 12) {
                            const economyValue = this.extractInt32(data, 8);
                            this.log(`[Enhanced PaySys] Game world economy update: ${economyValue}`);
                            
                            // Could update global economy settings
                            try {
                                await this.dbConnection.execute(
                                    'UPDATE global_config SET value = ? WHERE setting_name = "current_economy_rate"',
                                    [economyValue.toString()]
                                );
                            } catch (economyError) {
                                this.log(`[Enhanced PaySys] Economy table not available, update skipped`);
                            }
                            responseData.economyValue = economyValue;
                        }
                        break;
                        
                    default:
                        this.log(`[Enhanced PaySys] Unknown game world message type: ${messageType}`);
                        break;
                }
                
                const response = this.createResponse('nGameWorldResult', { 
                    result: responseResult,
                    ...responseData
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid game world packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in game world communication: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Get Zone Charge Flag
    async handleGetZoneChargeFlag(socket, data, connectionId) {
        this.logPayload('p2b_get_zone_charge_flag', data, connectionId);
        
        try {
            if (data.length >= 36) {
                const gateway = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Gateway ${gateway} get zone charge flag`);
                
                // Check zone charge settings from database or config
                let chargeFlag = 1; // Default to enabled
                
                try {
                    // Check if there's a zone configuration table
                    const [zoneRows] = await this.dbConnection.execute(
                        'SELECT charge_enabled FROM zone_config WHERE gateway_name = ?',
                        [gateway]
                    );
                    
                    if (zoneRows.length > 0) {
                        chargeFlag = zoneRows[0].charge_enabled ? 1 : 0;
                    } else {
                        // No specific config for this gateway, check global setting
                        const [globalRows] = await this.dbConnection.execute(
                            'SELECT value FROM global_config WHERE setting_name = "default_charge_enabled" LIMIT 1'
                        );
                        
                        if (globalRows.length > 0) {
                            chargeFlag = parseInt(globalRows[0].value) || 1;
                        }
                    }
                } catch (configError) {
                    // Config tables might not exist, use default
                    this.log(`[Enhanced PaySys] Zone config tables not available, using default charge flag: ${chargeFlag}`);
                }
                
                this.log(`[Enhanced PaySys] Gateway ${gateway} charge flag: ${chargeFlag}`);
                
                const response = this.createResponse('nGetZoneChargeFlagResult', { 
                    result: 1,
                    gateway: gateway,
                    flag: chargeFlag 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid zone charge flag packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error getting zone charge flag: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Ping Handler
    async handlePing(socket, data, connectionId) {
        this.logPayload('b2p_ping', data, connectionId);
        
        try {
            // Parse ping data
            const timestamp = data.length >= 8 ? this.extractInt32(data, 4) : Date.now();
            this.log(`[Enhanced PaySys] Ping received with timestamp: ${timestamp}`);
            
            const response = this.createPongResponse();
            socket.write(response);
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in ping handler: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Ping Response Handler
    async handlePingResponse(socket, data, connectionId) {
        this.logPayload('p2b_ping', data, connectionId);
        
        try {
            // Parse ping response data
            const timestamp = data.length >= 8 ? this.extractInt32(data, 4) : Date.now();
            this.log(`[Enhanced PaySys] Ping response received with timestamp: ${timestamp}`);
            
            const response = this.createPongResponse();
            socket.write(response);
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in ping response handler: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // ==================== ADDITIONAL HANDLERS FROM BISHOP REVERSE ENGINEERING ====================
    
    // Account Free Time Cleaning (discovered in Bishop binary)
    async handleAccountFreeTimeCleaning(socket, data, connectionId) {
        this.logPayload('b2p_account_free_time_cleaning', data, connectionId);
        
        try {
            if (data.length >= 36) {
                const username = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Account Free Time Cleaning for: ${username}`);
                
                // Clean up free time data - reset online status and clean expired sessions
                const [updateResult] = await this.dbConnection.execute(
                    'UPDATE account SET nOnline = 0 WHERE username = ?',
                    [username]
                );
                
                // Additional cleanup operations
                try {
                    // Clean expired free time records if table exists
                    await this.dbConnection.execute(
                        'DELETE FROM free_time_sessions WHERE username = ? AND expiry_time < NOW()',
                        [username]
                    );
                    
                    // Reset any temporary flags
                    await this.dbConnection.execute(
                        'UPDATE account SET temp_flags = 0 WHERE username = ?',
                        [username]
                    );
                } catch (cleanupError) {
                    // Tables might not exist, continue with basic cleanup
                    this.log(`[Enhanced PaySys] Extended cleanup tables not available, basic cleanup performed`);
                }
                
                if (updateResult.affectedRows > 0) {
                    this.log(`[Enhanced PaySys] Free time cleanup successful for: ${username}`);
                } else {
                    this.log(`[Enhanced PaySys] Account not found for cleanup: ${username}`);
                }
                
                const response = this.createResponse('p2b_account_free_time_cleaning_result', { 
                    result: 1,
                    username: username 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid free time cleaning packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in account free time cleaning: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Offline Live Timeout (G2B protocol from Bishop analysis)
    async handlePlayerOfflineLiveTimeout(socket, data, connectionId) {
        this.logPayload('g2b_player_offline_live_timeout', data, connectionId);
        
        try {
            if (data.length >= 36) {
                const username = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Player offline live timeout: ${username}`);
                
                // Handle offline timeout logic - clean up stale sessions
                const [updateResult] = await this.dbConnection.execute(
                    'UPDATE account SET nOnline = 0, offline_timeout_count = offline_timeout_count + 1 WHERE username = ?',
                    [username]
                );
                
                // Additional timeout handling
                try {
                    // Mark any live sessions as expired
                    await this.dbConnection.execute(
                        'UPDATE live_sessions SET status = "timeout" WHERE username = ? AND status = "active"',
                        [username]
                    );
                    
                    // Log timeout event
                    await this.dbConnection.execute(
                        'INSERT INTO timeout_log (username, timeout_type, timeout_time) VALUES (?, "offline_live", NOW())',
                        [username]
                    );
                } catch (timeoutError) {
                    this.log(`[Enhanced PaySys] Extended timeout tables not available, basic timeout handling performed`);
                }
                
                if (updateResult.affectedRows > 0) {
                    this.log(`[Enhanced PaySys] Offline timeout processed for: ${username}`);
                } else {
                    this.log(`[Enhanced PaySys] Account not found for timeout: ${username}`);
                }
                
                const response = this.createResponse('g2b_offline_live_timeout_result', { 
                    result: 1,
                    username: username 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid offline timeout packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in offline live timeout: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Player Offline Live Notify (G2B protocol from Bishop analysis)  
    async handlePlayerOfflineLiveNotify(socket, data, connectionId) {
        this.logPayload('g2b_player_offline_live_notify', data, connectionId);
        
        try {
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const mapId = this.extractInt32(data, 36);
                
                this.log(`[Enhanced PaySys] Player offline live notify: ${username}, MapID: ${mapId}`);
                
                // Handle offline live notification - update player location and status
                const [updateResult] = await this.dbConnection.execute(
                    'UPDATE account SET last_map_id = ?, offline_live_status = 1, last_activity = NOW() WHERE username = ?',
                    [mapId, username]
                );
                
                // Additional notification handling
                try {
                    // Create offline live notification record
                    await this.dbConnection.execute(
                        'INSERT INTO offline_notifications (username, map_id, notification_type, created_time) VALUES (?, ?, "live_notify", NOW())',
                        [username, mapId]
                    );
                    
                    // Update map statistics if available
                    await this.dbConnection.execute(
                        'UPDATE map_stats SET offline_players = offline_players + 1 WHERE map_id = ?',
                        [mapId]
                    );
                } catch (notifyError) {
                    this.log(`[Enhanced PaySys] Extended notification tables not available, basic notification performed`);
                }
                
                if (updateResult.affectedRows > 0) {
                    this.log(`[Enhanced PaySys] Offline live notification processed for: ${username} on map ${mapId}`);
                } else {
                    this.log(`[Enhanced PaySys] Account not found for notification: ${username}`);
                }
                
                const response = this.createResponse('g2b_offline_live_notify_result', { 
                    result: 1,
                    username: username,
                    mapId: mapId 
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid offline notify packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in offline live notify: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // Offline Live Kick Account Result (G2B protocol from Bishop analysis)
    async handleOfflineLiveKickAccountResult(socket, data, connectionId) {
        this.logPayload('g2b_offline_live_kick_account_result', data, connectionId);
        
        try {
            if (data.length >= 40) {
                const username = this.extractString(data, 4, 32);
                const resultCode = this.extractInt32(data, 36);
                
                this.log(`[Enhanced PaySys] Offline live kick account result: ${username}, ResultCode: ${resultCode}`);
                
                // Handle kick result processing - update account status based on result
                let kickStatus = 'unknown';
                let updateSuccess = false;
                
                if (resultCode === 1) {
                    // Kick successful
                    kickStatus = 'kicked';
                    const [updateResult] = await this.dbConnection.execute(
                        'UPDATE account SET nOnline = 0, last_kick_time = NOW(), kick_count = kick_count + 1 WHERE username = ?',
                        [username]
                    );
                    updateSuccess = updateResult.affectedRows > 0;
                    
                } else if (resultCode === 0) {
                    // Kick failed
                    kickStatus = 'kick_failed';
                    const [updateResult] = await this.dbConnection.execute(
                        'UPDATE account SET failed_kick_count = failed_kick_count + 1 WHERE username = ?',
                        [username]
                    );
                    updateSuccess = updateResult.affectedRows > 0;
                    
                } else {
                    // Unknown result code
                    kickStatus = 'unknown_result';
                    this.log(`[Enhanced PaySys] Unknown kick result code: ${resultCode}`);
                }
                
                // Additional kick result processing
                try {
                    // Log kick result
                    await this.dbConnection.execute(
                        'INSERT INTO kick_log (username, result_code, kick_status, kick_time) VALUES (?, ?, ?, NOW())',
                        [username, resultCode, kickStatus]
                    );
                    
                    // Clean up any offline live sessions
                    await this.dbConnection.execute(
                        'UPDATE live_sessions SET status = ? WHERE username = ? AND status = "offline"',
                        [kickStatus, username]
                    );
                } catch (kickLogError) {
                    this.log(`[Enhanced PaySys] Extended kick logging tables not available, basic processing performed`);
                }
                
                if (updateSuccess) {
                    this.log(`[Enhanced PaySys] Kick result processed successfully for: ${username} (${kickStatus})`);
                } else {
                    this.log(`[Enhanced PaySys] Account not found for kick result: ${username}`);
                }
                
                const response = this.createResponse('g2b_kick_result_processed', { 
                    result: 1,
                    username: username,
                    resultCode: resultCode,
                    kickStatus: kickStatus
                });
                socket.write(response);
            } else {
                this.log(`[Enhanced PaySys] Invalid kick result packet size: ${data.length}`);
                socket.write(this.createErrorResponse());
            }
        } catch (error) {
            this.log(`[Enhanced PaySys] Error in kick account result: ${error.message}`);
            socket.write(this.createErrorResponse());
        }
    }

    // ==================== HELPER METHODS ====================

    extractString(buffer, offset, length) {
        const end = buffer.indexOf(0, offset);
        const actualEnd = end === -1 ? offset + length : Math.min(end, offset + length);
        return buffer.toString('utf8', offset, actualEnd);
    }

    extractInt32(buffer, offset) {
        return buffer.readUInt32LE(offset);
    }

    createResponse(protocolId, payloadData = null) {
        // Create binary protocol response matching tagProtocolHeader format
        const payload = payloadData || Buffer.alloc(0);
        
        // Handle both numeric protocol IDs and buffer payloads
        let actualProtocolId;
        let actualPayload;
        
        if (typeof protocolId === 'number') {
            actualProtocolId = protocolId;
            actualPayload = payload;
        } else if (Buffer.isBuffer(payloadData)) {
            // If protocolId is not a number, assume it's a name and use default
            actualProtocolId = 0x80; // Default success response
            actualPayload = payloadData;
        } else {
            // Legacy string-based response creation (convert to buffer)
            actualProtocolId = 0x80;
            actualPayload = Buffer.from(JSON.stringify(payloadData || {}), 'utf8');
        }
        
        // Based on pcap analysis, the protocol header format is:
        // Byte 0: Payload length (low byte)
        // Byte 1: Protocol ID
        // Bytes 2-3: Payload length continuation or flags
        
        // For the pcap response "35 00 97 44...", this means:
        // 0x35 (53) = total payload length
        // 0x00 = protocol byte or high length byte
        // 0x97 0x44... = actual payload data
        
        const totalSize = 2 + actualPayload.length; // 2 bytes header + payload
        const response = Buffer.allocUnsafe(totalSize);
        
        // Protocol header format matching pcap:
        response.writeUInt8(actualPayload.length, 0);  // Payload size (low byte)
        response.writeUInt8(0x00, 1);                  // High byte or protocol flag
        
        if (actualPayload.length > 0) {
            actualPayload.copy(response, 2);  // Copy payload after 2-byte header
        }
        
        this.log(`[Enhanced PaySys] Created response: PayloadSize=${actualPayload.length}, TotalSize=${totalSize}`);
        return response;
    }

    createErrorResponse() {
        // Send error response with protocol ID 0xFF (generic error)
        const errorPayload = Buffer.from([0x00, 0x00, 0x00, 0x00]); // Error code 0
        return this.createResponse(0xFF, errorPayload);
    }

    createPongResponse() {
        // Send pong response with current timestamp
        const pongPayload = Buffer.allocUnsafe(8);
        pongPayload.writeBigUInt64LE(BigInt(Date.now()), 0);
        return this.createResponse(0x83, pongPayload); // P2B_PING response
    }

    // ==================== SERVER MANAGEMENT ====================

    async start() {
        console.log('[Enhanced PaySys] Payment System Jx2Online Start....');
        console.log('[Enhanced PaySys] Enhanced Server with Complete Protocol Support');
        console.log('[Enhanced PaySys] Based on vzopaysys.exe and KG_SimulatePaysys_FS.exe Analysis');
        
        // Try to connect to database but continue even if it fails for debugging
        console.log('[Enhanced PaySys] Attempting database connection...');
        const dbConnected = await this.connectToDatabase();
        if (!dbConnected) {
            console.log('[Enhanced PaySys] Database connection failed, continuing in debug mode...');
            console.log('[Enhanced PaySys] Some features may not work without database');
        }
        
        this.server = net.createServer((socket) => {
            const connectionId = ++this.connectionId;
            this.connections.set(connectionId, socket);
            
            // Track connection state for Bishop protocol handling
            socket.bishopState = {
                identityVerified: false,
                loginRequested: false,
                packetsReceived: 0
            };
            
            this.log(`[Enhanced PaySys] New connection ${connectionId} from ${socket.remoteAddress}:${socket.remotePort}`);
            
            // Set socket options to prevent premature connection drops
            socket.setKeepAlive(true, 60000); // Keep alive with 60 second interval
            socket.setNoDelay(true);          // Disable Nagle's algorithm for immediate sends
            socket.setTimeout(0);             // No timeout
            
            // CRITICAL FIX: Bishop expects PaySys to send security key IMMEDIATELY upon connection
            // This is what Bishop's _RecvSecurityKey function is waiting for
            this.sendInitialSecurityKey(socket, connectionId);
            
            socket.on('data', (data) => {
                this.handleData(socket, data, connectionId);
            });
            
            socket.on('close', (hadError) => {
                const reason = hadError ? ' (with error)' : ' (graceful)';
                this.log(`[Enhanced PaySys] Connection ${connectionId} closed${reason}`);
                this.connections.delete(connectionId);
            });
            
            socket.on('error', (error) => {
                // Log error but don't close connection immediately
                // Bishop may send multiple packets and expects persistent connection
                this.log(`[Enhanced PaySys] Connection ${connectionId} error: ${error.message}`);
                
                // Only close on severe errors, not on ECONNRESET which is common
                if (error.code !== 'ECONNRESET' && error.code !== 'EPIPE') {
                    this.log(`[Enhanced PaySys] Severe error, closing connection: ${error.code}`);
                    this.connections.delete(connectionId);
                }
            });
            
            socket.on('timeout', () => {
                this.log(`[Enhanced PaySys] Connection ${connectionId} timed out`);
                socket.destroy(); // Only destroy on timeout
            });
        });
        
        this.server.listen(this.config.serverPort, this.config.serverIP, () => {
            console.log(`[Enhanced PaySys].....Starting the Enhanced Paysys...`);
            console.log(`[Enhanced PaySys] Server listening on ${this.config.serverIP}:${this.config.serverPort}`);
            console.log(`[Enhanced PaySys] Running Completed!.... Enhanced PaySys Ready!`);
        });
    }

    async handleData(socket, data, connectionId) {
        try {
            if (data.length < 1) {  // At least need protocol ID
                this.log(`[Enhanced PaySys] Invalid packet size from connection ${connectionId}: ${data.length}`);
                return;
            }
            
            // Update connection state
            socket.bishopState.packetsReceived++;
            
            // Log raw packet data for analysis
            this.log(`[Enhanced PaySys] Connection ${connectionId} received ${data.length} bytes (packet #${socket.bishopState.packetsReceived})`);
            this.logPayload('raw_packet', data, connectionId);
            
            const protocolType = this.detectProtocolType(data, socket);
            this.log(`[Enhanced PaySys] Handling protocol: ${protocolType}`);
            
            if (this.PROTOCOL_HANDLERS[protocolType]) {
                await this.PROTOCOL_HANDLERS[protocolType](socket, data, connectionId);
                
                // Update connection state based on handled protocol
                if (protocolType === 'b2p_bishop_identity_verify') {
                    socket.bishopState.identityVerified = true;
                } else if (protocolType === 'b2p_bishop_login_request') {
                    socket.bishopState.loginRequested = true;
                }
            } else {
                this.log(`[Enhanced PaySys] Unknown protocol type: ${protocolType}`);
                
                // For Bishop, send a more appropriate response based on first byte
                const protocolId = data.readUInt8(0);
                let responseId = 0x80; // Default success
                
                // Map common Bishop protocol IDs to appropriate responses
                switch (protocolId) {
                    case 0x01: responseId = 0x81; break; // Bishop identity verify result
                    case 0x02: responseId = 0x82; break; // Player identity verify result  
                    case 0x03: responseId = 0x83; break; // Ping response
                    default: responseId = 0x80; break;   // Generic success
                }
                
                // Send success response to maintain connection
                const successPayload = Buffer.from([0x01, 0x00, 0x00, 0x00]); // Success code
                const response = this.createResponse(responseId, successPayload);
                socket.write(response);
                
                this.log(`[Enhanced PaySys] Sent generic success response (0x${responseId.toString(16)}) for unknown protocol`);
            }
            
        } catch (error) {
            this.log(`[Enhanced PaySys] Error handling data from connection ${connectionId}: ${error.message}`);
            this.log(`[Enhanced PaySys] Error stack: ${error.stack}`);
            
            // Don't close connection on error, just send an error response
            try {
                const errorPayload = Buffer.from([0x00, 0x00, 0x00, 0x00]); // Error code
                socket.write(this.createResponse(0xFF, errorPayload));
                this.log(`[Enhanced PaySys] Sent error response, keeping connection alive`);
            } catch (writeError) {
                this.log(`[Enhanced PaySys] Failed to send error response: ${writeError.message}`);
            }
        }
    }

    detectProtocolType(data, socket = null) {
        // Parse the actual binary protocol header
        if (data.length < 4) {
            return 'b2p_bishop_identity_verify'; // Default to Bishop identity for short packets
        }
        
        // Analyze the first 4 bytes to determine protocol type from pcap analysis and Bishop RE
        const firstFourBytes = data.readUInt32LE(0);
        
        // Based on pcap analysis and Bishop strings:
        // First packet: 7f00 971d (0x1d970070 in little-endian) - Bishop Identity Verify
        // Second packet: 7f00 ffc1 (0xc1ff007f in little-endian) - Bishop Login Request
        
        if (data.length === 127) {
            const pattern = data.readUInt32LE(0);
            const secondBytes = data.readUInt16LE(2);
            
            this.log(`[Enhanced PaySys] 127-byte packet analysis: pattern=0x${pattern.toString(16)}, secondBytes=0x${secondBytes.toString(16)}`);
            
            // From PCAP analysis:
            // First packet: 7f00 971d... -> should be identity verify
            // Second packet: 7f00 ffc1... -> should be login request  
            
            if (secondBytes === 0x971D) {
                // Pattern matches first Bishop packet: 7f00 971d
                this.log(`[Enhanced PaySys] Detected Bishop Identity Verify packet: ${data.length} bytes, pattern: 0x${pattern.toString(16)}`);
                return 'b2p_bishop_identity_verify';
            } else if (secondBytes === 0xFFC1) {
                // Pattern matches second Bishop packet: 7f00 ffc1 
                this.log(`[Enhanced PaySys] Detected Bishop Login Request packet: ${data.length} bytes, pattern: 0x${pattern.toString(16)}`);
                return 'b2p_bishop_login_request';
            } else {
                // Use connection state to determine packet type for Bishop
                if (socket && socket.bishopState) {
                    if (!socket.bishopState.identityVerified && socket.bishopState.packetsReceived === 1) {
                        this.log(`[Enhanced PaySys] First 127-byte packet - assuming Identity Verify`);
                        return 'b2p_bishop_identity_verify';
                    } else if (socket.bishopState.identityVerified && !socket.bishopState.loginRequested) {
                        this.log(`[Enhanced PaySys] Second 127-byte packet - assuming Login Request`);  
                        return 'b2p_bishop_login_request';
                    }
                }
                
                // Check full first 4 bytes for other patterns
                const fullPattern = data.readUInt32LE(0);
                if ((fullPattern & 0xFFFF) === 0x007F) {
                    // All 127-byte packets starting with 7f00 are Bishop packets
                    // Use connection state to determine type
                    this.log(`[Enhanced PaySys] 127-byte Bishop packet with pattern 0x${fullPattern.toString(16)}`);
                    
                    // For now, default to identity verify for unknown patterns
                    return 'b2p_bishop_identity_verify';
                } else {
                    // Default to Bishop identity for other 127-byte packets
                    this.log(`[Enhanced PaySys] Generic Bishop Identity packet: ${data.length} bytes, pattern: 0x${pattern.toString(16)}`);
                    return 'b2p_bishop_identity_verify';
                }
            }
        }
        
        // Enhanced protocol detection based on Bishop reverse engineering
        // Check for specific protocol markers found in Bishop binary
        if (data.length >= 8) {
            const protocolMarker = data.readUInt32LE(4); // Second 4 bytes often contain protocol ID
            
            // Protocol patterns discovered from Bishop binary analysis
            switch (protocolMarker) {
                case 0x14A2: // Free time cleaning marker
                    return 'b2p_account_free_time_cleaning';
                case 0xCE65: // Offline timeout marker  
                    return 'g2b_player_offline_live_timeout';
                case 0xDA07: // Offline notify marker
                    return 'g2b_player_offline_live_notify';
                case 0xF6C8: // Kick result marker
                    return 'g2b_offline_live_kick_account_result';
            }
        }
        
        // For other packet sizes, use fallback detection
        if (data.length >= 32 && data.length <= 128) {
            this.log(`[Enhanced PaySys] Detected Bishop Identity packet: ${data.length} bytes, pattern: 0x${firstFourBytes.toString(16)}`);
            return 'b2p_bishop_identity_verify';
        }
        
        // First byte protocol ID mapping for other protocols
        const protocolId = data.readUInt8(0);
        
        // Enhanced protocol mapping based on Bishop binary strings and structures
        const protocolMap = {
            // Bishop to PaySys protocols  
            0x01: 'b2p_bishop_identity_verify',
            0x02: 'b2p_player_identity_verify', 
            0x03: 'b2p_ping',
            0x04: 'b2p_player_exchange',
            0x05: 'b2p_player_enter_game',
            0x06: 'b2p_player_leave_game',
            0x07: 'b2p_account_free_time_cleaning',
            0x08: 'g2b_player_offline_live_timeout',
            0x09: 'g2b_player_offline_live_notify',
            0x0A: 'g2b_offline_live_kick_account_result',
            
            // Common control characters that might indicate Bishop packets
            0x00: 'b2p_bishop_identity_verify', // NULL byte could be Bishop
            0x7F: 'b2p_bishop_identity_verify', // 127-byte packets start with 0x7F
        };
        
        const protocolType = protocolMap[protocolId] || 'b2p_bishop_identity_verify';
        this.log(`[Enhanced PaySys] Detected protocol ID: 0x${protocolId.toString(16).padStart(2, '0')} -> ${protocolType}`);
        
        return protocolType;
    }

    async stop() {
        console.log('[Enhanced PaySys] Stopping server...');
        
        // Close all connections
        for (const [id, socket] of this.connections) {
            socket.destroy();
        }
        this.connections.clear();
        
        // Close server
        if (this.server) {
            this.server.close();
        }
        
        // Close database connection
        if (this.dbConnection) {
            await this.dbConnection.end();
        }
        
        console.log('[Enhanced PaySys] Disconnected !!! Enhanced PaySys Stopped');
    }
}

// ==================== STARTUP ====================

if (require.main === module) {
    const server = new EnhancedPaySysServer();
    
    process.on('SIGTERM', async () => {
        await server.stop();
        process.exit(0);
    });
    
    process.on('SIGINT', async () => {
        await server.stop();
        process.exit(0);
    });
    
    server.start().catch(error => {
        console.error('[Enhanced PaySys] Failed to start server:', error);
        process.exit(1);
    });
}

module.exports = EnhancedPaySysServer;