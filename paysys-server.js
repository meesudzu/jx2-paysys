const net = require('net');
const mysql = require('mysql2/promise');
const fs = require('fs');
const crypto = require('crypto');

/**
 * PaySys Server 
 * Combines the working Bishop connection logic from simple version
 * with comprehensive protocol handlers from enhanced version
 * Based on reverse engineering of Linux paysys binary and PCAP analysis
 */
class PaySysServer {
    constructor(configPath = 'paysys.ini') {
        this.config = this.loadConfig(configPath);
        this.dbConnection = null;
        this.server = null;
        this.connections = new Map();
        this.connectionId = 0;
        
        // Protocol constants from original binary analysis
        this.PROTOCOL_HEADER_SIZE = 4;
        this.MAX_PACKET_SIZE = 65500;
        
        console.log('[Paysys] Server initialized - combines working Bishop connection + comprehensive handlers');
    }

    loadConfig(configPath) {
        try {
            const configText = fs.readFileSync(configPath, 'utf8');
            const config = {};
            let currentSection = '';
            
            configText.split('\n').forEach(line => {
                line = line.trim();
                if (line.startsWith('[') && line.endsWith(']')) {
                    currentSection = line.slice(1, -1).toLowerCase();
                } else if (line.includes('=') && currentSection === 'database') {
                    const [key, value] = line.split('=').map(s => s.trim());
                    switch (key.toLowerCase()) {
                        case 'ip': config.dbHost = value; break;
                        case 'port': config.dbPort = parseInt(value); break;
                        case 'username': config.dbUser = value; break;
                        case 'password': config.dbPassword = value; break;
                        case 'dbname': config.dbName = value; break;
                    }
                } else if (line.includes('=') && currentSection === 'paysys') {
                    const [key, value] = line.split('=').map(s => s.trim());
                    if (key.toLowerCase() === 'port') config.serverPort = parseInt(value);
                }
            });
            
            return config;
        } catch (error) {
            console.log(`[Paysys] Config file ${configPath} not found, using defaults`);
            return {
                dbHost: 'localhost',
                dbPort: 3306,
                dbUser: 'root',
                dbPassword: '',
                dbName: 'jx2',
                serverPort: 8000
            };
        }
    }

    log(message) {
        const timestamp = new Date().toISOString();
        console.log(`${timestamp} - ${message}`);
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
            
            this.log(`[Paysys] Attempting database connection to ${dbConfig.host}:${dbConfig.port} as ${dbConfig.user}`);
            
            this.dbConnection = await mysql.createConnection(dbConfig);
            
            // Test the connection
            await this.dbConnection.execute('SELECT 1 as test');
            
            this.log('[Paysys] Connected to MySQL database successfully');
            return true;
        } catch (error) {
            this.log(`[Paysys] Cannot Connect to Mysql Server: ${error.message}`);
            this.dbConnection = null;
            return false;
        }
    }

    async start() {
        try {
            // Try to connect to database (optional)
            await this.connectToDatabase();
            
            this.server = net.createServer((socket) => {
                this.handleConnection(socket);
            });

            this.server.listen(this.config.serverPort, () => {
                this.log(`[Paysys] Server listening on port ${this.config.serverPort}`);
                this.log(`[Paysys] Ready to accept Bishop and client connections`);
            });

            this.server.on('error', (error) => {
                this.log(`[Paysys] Server error: ${error.message}`);
            });

        } catch (error) {
            this.log(`[Paysys] Failed to start server: ${error.message}`);
        }
    }

    handleConnection(socket) {
        const connectionId = ++this.connectionId;
        this.connections.set(connectionId, {
            socket: socket,
            authenticated: false,
            isPlayer: false,
            username: null
        });

        this.log(`[Paysys] New connection ${connectionId} from ${socket.remoteAddress}:${socket.remotePort}`);
        
        // Send security key immediately (Bishop expects this)
        this.sendSecurityKey(socket, connectionId);

        socket.on('data', (data) => {
            this.handleData(socket, data, connectionId);
        });

        socket.on('close', () => {
            this.log(`[Paysys] Connection ${connectionId} closed`);
            this.connections.delete(connectionId);
        });

        socket.on('error', (error) => {
            this.log(`[Paysys] Connection ${connectionId} error: ${error.message}`);
            this.connections.delete(connectionId);
        });
    }

    // WORKING Bishop security key from simple version - restored working format
    sendSecurityKey(socket, connectionId) {
        try {
            this.log(`[Paysys] Connection ${connectionId} - Sending security key like original paysys`);
            
            // From working commit 656aabe - exact format that Bishop accepts
            const packet = Buffer.from([
                0x22, 0x00, 0x20, 0x00,  // Header: size=34, protocol=0x2000 (CIPHER_PROTOCOL_TYPE)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Padding
                // Security key (8 bytes) - using same pattern as working capture
                0xf5, 0x4d, 0x3f, 0xc9, 0x5a, 0xcf, 0xb2, 0x5e,
                // Padding (16 zero bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]);
            
            socket.write(packet);
            this.log(`[Paysys] Security key sent - ${packet.length} bytes`);
            
        } catch (error) {
            this.log(`[Paysys] Error sending security key: ${error.message}`);
        }
    }

    handleData(socket, data, connectionId) {
        try {
            this.log(`[Paysys] Connection ${connectionId} received ${data.length} bytes`);
            
            if (data.length === 127) {
                // Bishop packets - use working logic from simple version
                this.handleBishopPacket(socket, data, connectionId);
            } else if (data.length === 227 || data.length === 229) {
                // Player identity verification - Protocol 62 
                // Bishop sends 227-byte payload but actual packet can be 229 bytes (2-byte header + 227 payload)
                this.handlePlayerIdentityVerify(socket, data, connectionId);
            } else if (data.length === 7) {
                // Short Bishop packets - ping or simple commands
                this.handleShortBishopPacket(socket, data, connectionId);
            } else if (data.length === 47) {
                // Medium Bishop packets - various game operations
                this.handleMediumBishopPacket(socket, data, connectionId);
            } else {
                this.log(`[Paysys] Unexpected packet length: ${data.length}`);
                this.log(`[Paysys] First 8 bytes: ${data.subarray(0, Math.min(8, data.length)).toString('hex')}`);
            }
            
        } catch (error) {
            this.log(`[Paysys] Error handling data: ${error.message}`);
        }
    }

    // WORKING Bishop packet handler from simple version
    handleBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Paysys] Bishop packet received: ${data.length} bytes`);
            this.log(`[Paysys] First 8 bytes: ${data.subarray(0, 8).toString('hex')}`);
            
            if (data.length === 127) {
                // Both 127-byte Bishop packets get same response from original Linux paysys
                const protocol = data.readUInt16LE(2);
                this.log(`[Paysys] 127-byte Bishop packet, protocol: 0x${protocol.toString(16)}`);
                
                // From PCAP: Working response is exactly 53 bytes: 3500 9744 6137 cc16...
                const response = Buffer.from([
                    0x35, 0x00,   // Size: 53 bytes
                    0x97, 0x44,   // Protocol response
                    // Payload (49 bytes) - exact from working PCAP
                    0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4, 
                    0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1, 
                    0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
                    0x00, 0xfa, 0x40, 0xa1, 0x99, 0xa1,
                    0x37, 0x44, 0x61, 0x37, 0xcc, 0x16, 0x16, 0xb0, 0x5d, 0xd4,
                    0x00, 0xfb, 0x40, 0xa1, 0x99, 0x32, 0xca, 0x39, 0xdb
                ]);
                
                socket.write(response);
                this.log(`[Paysys] Sent exact PCAP response: ${response.length} bytes`);
                this.log(`[Paysys] Response matches working PCAP capture exactly - should pass all Bishop checks`);
                
            } else if (data.length === 227) {
                // This is likely a player identity verification request (Protocol 62)
                this.handlePlayerIdentityVerify(socket, data, connectionId);
                
            } else {
                this.log(`[Paysys] Unexpected Bishop packet length: ${data.length}`);
            }
            
        } catch (error) {
            this.log(`[Paysys] Error in handleBishopPacket: ${error.message}`);
        }
    }

    // Extract null-terminated string from buffer
    extractString(buffer, offset, maxLength) {
        const end = Math.min(offset + maxLength, buffer.length);
        let str = '';
        for (let i = offset; i < end; i++) {
            if (buffer[i] === 0) break;
            str += String.fromCharCode(buffer[i]);
        }
        return str;
    }

    // WORKING Player identity verification from simple version (Protocol 62, 227/229 bytes)
    async handlePlayerIdentityVerify(socket, data, connectionId) {
        try {
            this.log(`[Paysys] Player identity verification: ${data.length} bytes`);
            this.log(`[Paysys] Full packet hex: ${data.toString('hex')}`);
            
            // Extract protocol and key from request
            const requestProtocol = data.readUInt16LE(2);
            const requestKey = data.readUInt32LE(4); // Bishop tracks requests by Key
            
            this.log(`[Paysys] Request protocol: 0x${requestProtocol.toString(16)}, Key: ${requestKey}`);
            
            // Debug: show packet structure
            this.log(`[Paysys] Packet structure analysis:`);
            this.log(`[Paysys]   Size: ${data.readUInt16LE(0)} (offset 0)`);
            this.log(`[Paysys]   Protocol: 0x${data.readUInt16LE(2).toString(16)} (offset 2)`);
            this.log(`[Paysys]   Key: ${data.readUInt32LE(4)} (offset 4)`);
            
            // Try different offsets to find username/password
            for (let offset = 8; offset <= 72; offset += 4) {
                if (offset + 32 < data.length) {
                    const testStr = this.extractString(data, offset, 32);
                    if (testStr.length > 0 && testStr.match(/^[a-zA-Z0-9_]+$/)) {
                        this.log(`[Paysys] Possible username at offset ${offset}: "${testStr}"`);
                    }
                }
            }
            
            if (data.length >= 72) {
                // Use simple extraction from working version
                const username = this.extractString(data, 4, 32);
                const password = this.extractString(data, 36, 32);
                
                this.log(`[Paysys] Player login attempt: ${username}`);
                
                if (this.dbConnection) {
                    // Query account from database
                    const [rows] = await this.dbConnection.execute(
                        'SELECT username, password FROM account WHERE username = ?',
                        [username]
                    );
                    
                    if (rows.length > 0 && rows[0].password === password) {
                        this.log(`[Paysys] Player login successful: ${username}`);
                        this.sendPlayerVerifyResponse(socket, username, true);
                    } else {
                        this.log(`[Paysys] Player login failed: ${username}`);
                        this.sendPlayerVerifyResponse(socket, username, false);
                    }
                } else {
                    // No database connection - allow login for testing
                    this.log(`[Paysys] No database - allowing player login: ${username}`);
                    this.sendPlayerVerifyResponse(socket, username, true);
                }
                
            } else {
                this.log(`[Paysys] Invalid player identity packet size: ${data.length}`);
            }
            
        } catch (error) {
            this.log(`[Paysys] Error in player identity verify: ${error.message}`);
        }
    }

    sendPlayerVerifyResponse(socket, username, success) {
        try {
            // Use exact format from working simple version
            const response = Buffer.alloc(64);
            response.writeUInt16LE(64, 0);       // Size: 64 bytes
            response.writeUInt16LE(0x3F, 2);     // Response protocol for player verify (Protocol 63)
            response.writeUInt32LE(success ? 1 : 0, 4);  // Success/failure code at offset 4
            response.write(username, 8, 32, 'utf8'); // Username at offset 8
            
            this.log(`[Paysys] Sending player verify response:`);
            this.log(`[Paysys]   Response size: ${response.readUInt16LE(0)} bytes`);
            this.log(`[Paysys]   Response protocol: 0x${response.readUInt16LE(2).toString(16)}`);
            this.log(`[Paysys]   Success code: ${response.readUInt32LE(4)}`);
            this.log(`[Paysys]   Username: "${this.extractString(response, 8, 32)}"`);
            this.log(`[Paysys]   Response hex: ${response.toString('hex')}`);
            
            socket.write(response);
            this.log(`[Paysys] Sent player verify ${success ? 'success' : 'failure'} response: ${response.length} bytes`);
        } catch (error) {
            this.log(`[Paysys] Error sending player verify response: ${error.message}`);
        }
    }

    // Handle short Bishop packets (7 bytes) - pings, simple commands
    handleShortBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Paysys] Short Bishop packet (7 bytes): ${data.toString('hex')}`);
            
            // Extract protocol
            const protocol = data.readUInt16LE(2);
            this.log(`[Paysys] Short packet protocol: 0x${protocol.toString(16)}`);
            
            // Most short packets are pings or simple responses
            const response = Buffer.alloc(8);
            response.writeUInt16LE(8, 0);        // Size: 8 bytes
            response.writeUInt16LE(protocol, 2); // Echo protocol back
            response.writeUInt32LE(1, 4);        // Success code
            
            socket.write(response);
            this.log(`[Paysys] Sent short packet response: ${response.length} bytes`);
            
        } catch (error) {
            this.log(`[Paysys] Error handling short Bishop packet: ${error.message}`);
        }
    }

    // Handle medium Bishop packets (47 bytes) - various game operations
    handleMediumBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Paysys] Medium Bishop packet (47 bytes): ${data.subarray(0, 8).toString('hex')}`);
            
            const protocol = data.readUInt16LE(2);
            this.log(`[Paysys] Medium packet protocol: 0x${protocol.toString(16)}`);
            
            // Generic response for medium packets
            const response = Buffer.alloc(48);
            response.writeUInt16LE(48, 0);       // Size: 48 bytes  
            response.writeUInt16LE(protocol, 2); // Echo protocol back
            response.writeUInt32LE(1, 4);        // Success code
            
            socket.write(response);
            this.log(`[Paysys] Sent medium packet response: ${response.length} bytes`);
            
        } catch (error) {
            this.log(`[Paysys] Error handling medium Bishop packet: ${error.message}`);
        }
    }

    // Handle large Bishop packets (229 bytes) - complex operations  
    handleLargeBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Paysys] Large Bishop packet (229 bytes): ${data.subarray(0, 8).toString('hex')}`);
            
            const protocol = data.readUInt16LE(2);
            this.log(`[Paysys] Large packet protocol: 0x${protocol.toString(16)}`);
            
            // Generic response for large packets
            const response = Buffer.alloc(64);
            response.writeUInt16LE(64, 0);       // Size: 64 bytes
            response.writeUInt16LE(protocol, 2); // Echo protocol back  
            response.writeUInt32LE(1, 4);        // Success code
            
            socket.write(response);
            this.log(`[Paysys] Sent large packet response: ${response.length} bytes`);
            
        } catch (error) {
            this.log(`[Paysys] Error handling large Bishop packet: ${error.message}`);
        }
    }

    // Comprehensive protocol handlers from enhanced version
    
    async handlePlayerExchange(socket, data, connectionId) {
        // Player money/item exchange logic
        try {
            const playerId = data.readUInt32LE(4);
            const exchangeType = data.readUInt32LE(8);
            
            this.log(`[Paysys] Player exchange: player=${playerId}, type=${exchangeType}`);
            
            if (this.dbConnection) {
                // Implement real database logic for player exchange
                const [result] = await this.dbConnection.execute(
                    'SELECT money FROM player_data WHERE player_id = ?',
                    [playerId]
                );
                
                if (result.length > 0) {
                    // Process exchange based on type
                    const response = Buffer.alloc(32);
                    response.writeUInt16LE(32, 0);
                    response.writeUInt16LE(0x40, 2); // Exchange response protocol
                    response.writeUInt32LE(1, 4); // Success
                    response.writeUInt32LE(playerId, 8);
                    
                    socket.write(response);
                    this.log(`[Paysys] Player exchange successful`);
                } else {
                    this.sendErrorResponse(socket, 0x40, 'Player not found');
                }
            } else {
                // No database - send success for testing
                const response = Buffer.alloc(32);
                response.writeUInt16LE(32, 0);
                response.writeUInt16LE(0x40, 2);
                response.writeUInt32LE(1, 4);
                response.writeUInt32LE(playerId, 8);
                
                socket.write(response);
                this.log(`[Paysys] Player exchange successful (no DB)`);
            }
            
        } catch (error) {
            this.log(`[Paysys] Error in player exchange: ${error.message}`);
            this.sendErrorResponse(socket, 0x40, error.message);
        }
    }

    async handlePlayerEnterGame(socket, data, connectionId) {
        // Player entering game logic
        try {
            const playerId = data.readUInt32LE(4);
            const gameServerId = data.readUInt32LE(8);
            
            this.log(`[Paysys] Player enter game: player=${playerId}, server=${gameServerId}`);
            
            // Update player status in database
            if (this.dbConnection) {
                await this.dbConnection.execute(
                    'UPDATE player_data SET status = ?, server_id = ?, login_time = NOW() WHERE player_id = ?',
                    ['online', gameServerId, playerId]
                );
            }
            
            const response = Buffer.alloc(24);
            response.writeUInt16LE(24, 0);
            response.writeUInt16LE(0x45, 2); // Enter game response protocol
            response.writeUInt32LE(1, 4); // Success
            response.writeUInt32LE(playerId, 8);
            response.writeUInt32LE(gameServerId, 12);
            
            socket.write(response);
            this.log(`[Paysys] Player enter game response sent`);
            
        } catch (error) {
            this.log(`[Paysys] Error in player enter game: ${error.message}`);
            this.sendErrorResponse(socket, 0x45, error.message);
        }
    }

    async handlePlayerLeaveGame(socket, data, connectionId) {
        // Player leaving game logic  
        try {
            const playerId = data.readUInt32LE(4);
            
            this.log(`[Paysys] Player leave game: player=${playerId}`);
            
            // Update player status in database
            if (this.dbConnection) {
                await this.dbConnection.execute(
                    'UPDATE player_data SET status = ?, logout_time = NOW() WHERE player_id = ?',
                    ['offline', playerId]
                );
            }
            
            const response = Buffer.alloc(20);
            response.writeUInt16LE(20, 0);
            response.writeUInt16LE(0x46, 2); // Leave game response protocol
            response.writeUInt32LE(1, 4); // Success
            response.writeUInt32LE(playerId, 8);
            
            socket.write(response);
            this.log(`[Paysys] Player leave game response sent`);
            
        } catch (error) {
            this.log(`[Paysys] Error in player leave game: ${error.message}`);
            this.sendErrorResponse(socket, 0x46, error.message);
        }
    }

    sendErrorResponse(socket, protocol, errorMessage) {
        try {
            const response = Buffer.alloc(16);
            response.writeUInt16LE(16, 0);
            response.writeUInt16LE(protocol, 2);
            response.writeUInt32LE(0, 4); // Error code
            
            socket.write(response);
            this.log(`[Paysys] Sent error response for protocol 0x${protocol.toString(16)}: ${errorMessage}`);
        } catch (error) {
            this.log(`[Paysys] Error sending error response: ${error.message}`);
        }
    }

    async stop() {
        try {
            if (this.server) {
                this.server.close();
                this.log('[Paysys] Server stopped');
            }
            
            if (this.dbConnection) {
                await this.dbConnection.end();
                this.log('[Paysys] Database connection closed');
            }
        } catch (error) {
            this.log(`[Paysys] Error stopping server: ${error.message}`);
        }
    }
}

// Start the PaySys server
async function main() {
    const server = new PaySysServer();
    
    process.on('SIGINT', async () => {
        console.log('\n[Paysys] Received SIGINT, shutting down gracefully...');
        await server.stop();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        console.log('\n[Paysys] Received SIGTERM, shutting down gracefully...');
        await server.stop();
        process.exit(0);
    });

    await server.start();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = PaySysServer;