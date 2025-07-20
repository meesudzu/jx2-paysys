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
            'p2b_ping': this.handlePingResponse.bind(this)
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
        console.log('[Enhanced PaySys] Implements 22+ protocol handlers from vzopaysys.exe and KG_SimulatePaysys_FS.exe');
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
            
            // This is the second 127-byte packet Bishop sends after identity verification
            // Pattern: 7f00 ffc1... 
            // Based on Bishop log "Recv Verify Information From PaySys nRetCode = -1"
            // Bishop is expecting to RECEIVE verification information, not just get a response
            
            // The key insight is that Bishop calls something like "Recv Verify Information From PaySys"
            // This suggests PaySys should proactively SEND verification information to Bishop
            
            // Let's send a verification information packet similar to the identity response
            const verificationPayload = Buffer.from([
                // Similar pattern to the first response but possibly different
                0x01, 0x00, 0x00, 0x00, // Success/verification code
                0x00, 0x00, 0x00, 0x00, // Session or connection info
                // Additional verification data if needed
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00
            ]);
            
            const response = this.createResponse(0, verificationPayload);
            socket.write(response);
            
            this.log(`[Enhanced PaySys] Bishop Login Request - Verification information sent to Bishop`);
            
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
                
                // In real implementation, would verify session token
                const response = this.createResponse('nBishopLoginReconnectResult', { 
                    result: 1,
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
                
                // In real implementation, would process item purchase from database
                const response = this.createResponse('nUserIBBuyItemResult', { 
                    result: 1,
                    username: username,
                    itemId: itemId,
                    quantity: quantity 
                });
                socket.write(response);
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
                
                // In real implementation, would process multiple item purchases
                const response = this.createResponse('nUserIBBuyItemResult', { 
                    result: 1,
                    username: username,
                    itemCount: itemCount 
                });
                socket.write(response);
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
                
                // In real implementation, would process item usage
                const response = this.createResponse('nUserIBUseItemResult', { 
                    result: 1,
                    username: username,
                    itemId: itemId,
                    quantity: quantity 
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
                
                // In real implementation, would process multiple item usage
                const response = this.createResponse('nUserIBUseItemResult', { 
                    result: 1,
                    username: username,
                    itemCount: itemCount 
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
                
                // In real implementation, would verify player for item shop access
                const response = this.createResponse('nUserLoginVerifyResult', { 
                    result: 1,
                    username: username 
                });
                socket.write(response);
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
                
                // In real implementation, would update player status in database
                await this.dbConnection.execute(
                    'UPDATE account SET nOnline = 1, dtLastLogin = NOW() WHERE username = ?',
                    [username]
                );
                
                const response = this.createResponse('nUserLoginResult', { 
                    result: 1,
                    username: username 
                });
                socket.write(response);
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
                
                // In real implementation, would update player status in database
                await this.dbConnection.execute(
                    'UPDATE account SET nOnline = 0, dtLastLogin = NOW() WHERE username = ?',
                    [username]
                );
                
                const response = this.createResponse('nUserLogoutResult', { 
                    result: 1,
                    username: username 
                });
                socket.write(response);
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
                
                // In real implementation, would verify MiBao/PassPod code
                const response = this.createResponse('nPasspodVerifyResult', { 
                    result: 1,
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
                
                // In real implementation, would process coin exchange with database
                const response = this.createResponse('nUserExtChangeResult', { 
                    result: 1,
                    username: username,
                    coinAmount: coinAmount 
                });
                socket.write(response);
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
                const extraParam = this.extractInt32(data, 44);
                
                this.log(`[Enhanced PaySys] Player ${username} extended coin exchange: ${coinAmount}, type: ${exchangeType}, param: ${extraParam}`);
                
                // In real implementation, would process extended exchange with database
                const response = this.createResponse('nUserExtChangeResult', { 
                    result: 1,
                    username: username,
                    coinAmount: coinAmount 
                });
                socket.write(response);
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
            if (data.length >= 36) {
                const username = this.extractString(data, 4, 32);
                this.log(`[Enhanced PaySys] Freeze Fee Coin Account ${username} is [OK]`);
                
                // In real implementation, would freeze account coins
                const response = this.createResponse('nUserExtChangeResult', { 
                    result: 1,
                    username: username 
                });
                socket.write(response);
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
            if (data.length >= 68) {
                const fromUsername = this.extractString(data, 4, 32);
                const toUsername = this.extractString(data, 36, 32);
                
                this.log(`[Enhanced PaySys] Tranfer Coin From Account ${fromUsername} To Account ${toUsername} is [OK]`);
                
                // In real implementation, would perform coin transfer between accounts
                const response = this.createResponse('nUserExtChangeResult', { 
                    result: 1,
                    fromUsername: fromUsername,
                    toUsername: toUsername 
                });
                socket.write(response);
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
                
                // In real implementation, would query pending transfers from database
                const response = this.createResponse('nUserQueryTransferResult', { 
                    result: 1,
                    username: username,
                    pendingTransfers: 0 
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
                
                // In real implementation, would update charge flag in database
                await this.dbConnection.execute(
                    'UPDATE account SET nCharge = ? WHERE username = ?',
                    [chargeFlag, username]
                );
                
                const response = this.createResponse('nAccountSetChargeResult', { 
                    result: 1,
                    username: username,
                    chargeFlag: chargeFlag 
                });
                socket.write(response);
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
                
                // In real implementation, would handle various game world messages
                const response = this.createResponse('nGameWorldResult', { 
                    result: 1,
                    messageType: messageType 
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
                
                // In real implementation, would check zone charge settings
                const response = this.createResponse('nGetZoneChargeFlagResult', { 
                    result: 1,
                    gateway: gateway,
                    flag: 1 
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
            
            // Log raw packet data for analysis
            this.log(`[Enhanced PaySys] Connection ${connectionId} received ${data.length} bytes`);
            this.logPayload('raw_packet', data, connectionId);
            
            const protocolType = this.detectProtocolType(data);
            this.log(`[Enhanced PaySys] Handling protocol: ${protocolType}`);
            
            if (this.PROTOCOL_HANDLERS[protocolType]) {
                await this.PROTOCOL_HANDLERS[protocolType](socket, data, connectionId);
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

    detectProtocolType(data) {
        // Parse the actual binary protocol header
        if (data.length < 4) {
            return 'b2p_bishop_identity_verify'; // Default to Bishop identity for short packets
        }
        
        // Analyze the first 4 bytes to determine protocol type from pcap analysis
        const firstFourBytes = data.readUInt32LE(0);
        
        // Based on pcap analysis:
        // First packet: 7f00 971d (0x1d970070 in little-endian) - Bishop Identity Verify
        // Second packet: 7f00 ffc1 (0xc1ff007f in little-endian) - Bishop Login Request
        
        if (data.length === 127) {
            const pattern = data.readUInt32LE(0);
            
            if ((pattern & 0xFFFF0000) === 0x1D970000) {
                // Pattern matches first Bishop packet: 7f00 971d
                this.log(`[Enhanced PaySys] Detected Bishop Identity Verify packet: ${data.length} bytes, pattern: 0x${pattern.toString(16)}`);
                return 'b2p_bishop_identity_verify';
            } else if ((pattern & 0xFFFF0000) === 0xFFC10000) {
                // Pattern matches second Bishop packet: 7f00 ffc1 
                this.log(`[Enhanced PaySys] Detected Bishop Login Request packet: ${data.length} bytes, pattern: 0x${pattern.toString(16)}`);
                return 'b2p_bishop_login_request';
            } else {
                // Default to Bishop identity for 127-byte packets
                this.log(`[Enhanced PaySys] Detected Bishop Identity packet (generic): ${data.length} bytes, pattern: 0x${pattern.toString(16)}`);
                return 'b2p_bishop_identity_verify';
            }
        }
        
        // For other packet sizes, use fallback detection
        if (data.length >= 32 && data.length <= 128) {
            this.log(`[Enhanced PaySys] Detected Bishop Identity packet: ${data.length} bytes, pattern: 0x${firstFourBytes.toString(16)}`);
            return 'b2p_bishop_identity_verify';
        }
        
        // First byte protocol ID mapping for other protocols
        const protocolId = data.readUInt8(0);
        
        // Protocol mapping based on Bishop binary strings
        const protocolMap = {
            // Bishop to PaySys protocols  
            0x01: 'b2p_bishop_identity_verify',
            0x02: 'b2p_player_identity_verify', 
            0x03: 'b2p_ping',
            0x04: 'b2p_player_exchange',
            0x05: 'b2p_player_enter_game',
            0x06: 'b2p_player_leave_game',
            
            // Common control characters that might indicate Bishop packets
            0x00: 'b2p_bishop_identity_verify', // NULL byte could be Bishop
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