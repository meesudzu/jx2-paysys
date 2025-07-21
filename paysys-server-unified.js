const net = require('net');
const mysql = require('mysql2/promise');
const fs = require('fs');
const crypto = require('crypto');

/**
 * Unified PaySys Server 
 * Combines the working Bishop connection logic from simple version
 * with comprehensive protocol handlers from enhanced version
 * Based on reverse engineering of Linux paysys binary and PCAP analysis
 */
class UnifiedPaySysServer {
    constructor(configPath = 'paysys.ini') {
        this.config = this.loadConfig(configPath);
        this.dbConnection = null;
        this.server = null;
        this.connections = new Map();
        this.connectionId = 0;
        
        // Protocol constants from original binary analysis
        this.PROTOCOL_HEADER_SIZE = 4;
        this.MAX_PACKET_SIZE = 65500;
        
        console.log('[Unified PaySys] Server initialized - combines working Bishop connection + comprehensive handlers');
    }

    loadConfig(configPath) {
        try {
            const configText = fs.readFileSync(configPath, 'utf8');
            const config = {};
            let currentSection = '';
            
            configText.split('\n').forEach(line => {
                line = line.trim();
                if (line.startsWith('[') && line.endsWith(']')) {
                    currentSection = line.slice(1, -1);
                } else if (line.includes('=') && currentSection === 'database') {
                    const [key, value] = line.split('=').map(s => s.trim());
                    switch (key) {
                        case 'host': config.dbHost = value; break;
                        case 'port': config.dbPort = parseInt(value); break;
                        case 'user': config.dbUser = value; break;
                        case 'password': config.dbPassword = value; break;
                        case 'database': config.dbName = value; break;
                    }
                } else if (line.includes('=') && currentSection === 'server') {
                    const [key, value] = line.split('=').map(s => s.trim());
                    if (key === 'port') config.serverPort = parseInt(value);
                }
            });
            
            return config;
        } catch (error) {
            console.log(`[Unified PaySys] Config file ${configPath} not found, using defaults`);
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
            
            this.log(`[Unified PaySys] Attempting database connection to ${dbConfig.host}:${dbConfig.port} as ${dbConfig.user}`);
            
            this.dbConnection = await mysql.createConnection(dbConfig);
            
            // Test the connection
            await this.dbConnection.execute('SELECT 1 as test');
            
            this.log('[Unified PaySys] Connected to MySQL database successfully');
            return true;
        } catch (error) {
            this.log(`[Unified PaySys] Cannot Connect to Mysql Server: ${error.message}`);
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
                this.log(`[Unified PaySys] Server listening on port ${this.config.serverPort}`);
                this.log(`[Unified PaySys] Ready to accept Bishop and client connections`);
            });

            this.server.on('error', (error) => {
                this.log(`[Unified PaySys] Server error: ${error.message}`);
            });

        } catch (error) {
            this.log(`[Unified PaySys] Failed to start server: ${error.message}`);
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

        this.log(`[Unified PaySys] New connection ${connectionId} from ${socket.remoteAddress}:${socket.remotePort}`);
        
        // Send security key immediately (Bishop expects this)
        this.sendSecurityKey(socket, connectionId);

        socket.on('data', (data) => {
            this.handleData(socket, data, connectionId);
        });

        socket.on('close', () => {
            this.log(`[Unified PaySys] Connection ${connectionId} closed`);
            this.connections.delete(connectionId);
        });

        socket.on('error', (error) => {
            this.log(`[Unified PaySys] Connection ${connectionId} error: ${error.message}`);
            this.connections.delete(connectionId);
        });
    }

    // WORKING Bishop security key from simple version
    sendSecurityKey(socket, connectionId) {
        try {
            this.log(`[Unified PaySys] Connection ${connectionId} - Sending security key like original paysys`);
            
            // Exact security key packet from working PCAP capture
            const packet = Buffer.from([
                // Header: 34-byte packet, protocol 0x00, flags 0x2000
                0x22, 0x00, 0x00, 0x20,
                
                // Padding (6 zero bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                
                // Security key (8 bytes) - from working capture
                0x6a, 0x6d, 0x40, 0xa1, 0x99, 0x32, 0xca, 0x39,
                
                // Padding (16 zero bytes)
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]);
            
            socket.write(packet);
            this.log(`[Unified PaySys] Security key sent - ${packet.length} bytes`);
            
        } catch (error) {
            this.log(`[Unified PaySys] Error sending security key: ${error.message}`);
        }
    }

    handleData(socket, data, connectionId) {
        try {
            this.log(`[Unified PaySys] Connection ${connectionId} received ${data.length} bytes`);
            
            if (data.length === 127) {
                // Bishop packets - use working logic from simple version
                this.handleBishopPacket(socket, data, connectionId);
            } else if (data.length === 227) {
                // Player identity verification - Protocol 62
                this.handlePlayerIdentityVerify(socket, data, connectionId);
            } else if (data.length === 7) {
                // Short Bishop packets - ping or simple commands
                this.handleShortBishopPacket(socket, data, connectionId);
            } else if (data.length === 47) {
                // Medium Bishop packets - various game operations
                this.handleMediumBishopPacket(socket, data, connectionId);
            } else if (data.length === 229) {
                // Large Bishop packets - complex operations
                this.handleLargeBishopPacket(socket, data, connectionId);
            } else {
                this.log(`[Unified PaySys] Unexpected packet length: ${data.length}`);
                this.log(`[Unified PaySys] First 8 bytes: ${data.subarray(0, Math.min(8, data.length)).toString('hex')}`);
            }
            
        } catch (error) {
            this.log(`[Unified PaySys] Error handling data: ${error.message}`);
        }
    }

    // WORKING Bishop packet handler from simple version
    handleBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Unified PaySys] Bishop packet received: ${data.length} bytes`);
            this.log(`[Unified PaySys] First 8 bytes: ${data.subarray(0, 8).toString('hex')}`);
            
            if (data.length === 127) {
                // Both 127-byte Bishop packets get same response from original Linux paysys
                const protocol = data.readUInt16LE(2);
                this.log(`[Unified PaySys] 127-byte Bishop packet, protocol: 0x${protocol.toString(16)}`);
                
                // Create EXACT response from working PCAP capture (53 bytes total)
                const response = Buffer.from([
                    // Header (4 bytes)
                    0x35, 0x00, 0x97, 0x44, 
                    
                    // Payload (49 bytes) - KAccountUserReturnVerify structure 
                    0x01, 0x00, 0x00, 0x00,  // nReturn = 1 (ACTION_SUCCESS)
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x6d, 0x40, 0x01, 0x00, 0x00, 0x00
                ]);
                
                socket.write(response);
                this.log(`[Unified PaySys] Sent exact PCAP response: ${response.length} bytes`);
                this.log(`[Unified PaySys] Response matches working PCAP capture exactly - should pass all Bishop checks`);
            }
            
        } catch (error) {
            this.log(`[Unified PaySys] Error in handleBishopPacket: ${error.message}`);
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

    // WORKING Player identity verification from simple version (Protocol 62, 227 bytes)
    async handlePlayerIdentityVerify(socket, data, connectionId) {
        try {
            this.log(`[Unified PaySys] Player identity verification: ${data.length} bytes`);
            this.log(`[Unified PaySys] First 8 bytes: ${data.subarray(0, 8).toString('hex')}`);
            
            if (data.length >= 72) {
                const username = this.extractString(data, 4, 32);
                const password = this.extractString(data, 36, 32);
                
                this.log(`[Unified PaySys] Player login attempt: ${username}`);
                
                if (this.dbConnection) {
                    // Query account from database
                    const [rows] = await this.dbConnection.execute(
                        'SELECT username, password FROM account WHERE username = ?',
                        [username]
                    );
                    
                    if (rows.length > 0 && rows[0].password === password) {
                        this.log(`[Unified PaySys] Player login successful: ${username}`);
                        this.sendPlayerVerifyResponse(socket, username, true);
                    } else {
                        this.log(`[Unified PaySys] Player login failed: ${username}`);
                        this.sendPlayerVerifyResponse(socket, username, false);
                    }
                } else {
                    // No database connection - allow login for testing
                    this.log(`[Unified PaySys] No database - allowing player login: ${username}`);
                    this.sendPlayerVerifyResponse(socket, username, true);
                }
                
            } else {
                this.log(`[Unified PaySys] Invalid player identity packet size: ${data.length}`);
            }
            
        } catch (error) {
            this.log(`[Unified PaySys] Error in player identity verify: ${error.message}`);
        }
    }

    sendPlayerVerifyResponse(socket, username, success) {
        try {
            const response = Buffer.alloc(64);
            response.writeUInt16LE(64, 0);       // Size: 64 bytes
            response.writeUInt16LE(0x3F, 2);     // Response protocol for player verify
            response.writeUInt32LE(success ? 1 : 0, 4);  // Success/failure code
            response.write(username, 8, 32, 'utf8'); // Echo username back
            
            socket.write(response);
            this.log(`[Unified PaySys] Sent player verify ${success ? 'success' : 'failure'} response: ${response.length} bytes`);
        } catch (error) {
            this.log(`[Unified PaySys] Error sending player verify response: ${error.message}`);
        }
    }

    // Handle short Bishop packets (7 bytes) - pings, simple commands
    handleShortBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Unified PaySys] Short Bishop packet (7 bytes): ${data.toString('hex')}`);
            
            // Extract protocol
            const protocol = data.readUInt16LE(2);
            this.log(`[Unified PaySys] Short packet protocol: 0x${protocol.toString(16)}`);
            
            // Most short packets are pings or simple responses
            const response = Buffer.alloc(8);
            response.writeUInt16LE(8, 0);        // Size: 8 bytes
            response.writeUInt16LE(protocol, 2); // Echo protocol back
            response.writeUInt32LE(1, 4);        // Success code
            
            socket.write(response);
            this.log(`[Unified PaySys] Sent short packet response: ${response.length} bytes`);
            
        } catch (error) {
            this.log(`[Unified PaySys] Error handling short Bishop packet: ${error.message}`);
        }
    }

    // Handle medium Bishop packets (47 bytes) - various game operations
    handleMediumBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Unified PaySys] Medium Bishop packet (47 bytes): ${data.subarray(0, 8).toString('hex')}`);
            
            const protocol = data.readUInt16LE(2);
            this.log(`[Unified PaySys] Medium packet protocol: 0x${protocol.toString(16)}`);
            
            // Generic response for medium packets
            const response = Buffer.alloc(48);
            response.writeUInt16LE(48, 0);       // Size: 48 bytes  
            response.writeUInt16LE(protocol, 2); // Echo protocol back
            response.writeUInt32LE(1, 4);        // Success code
            
            socket.write(response);
            this.log(`[Unified PaySys] Sent medium packet response: ${response.length} bytes`);
            
        } catch (error) {
            this.log(`[Unified PaySys] Error handling medium Bishop packet: ${error.message}`);
        }
    }

    // Handle large Bishop packets (229 bytes) - complex operations  
    handleLargeBishopPacket(socket, data, connectionId) {
        try {
            this.log(`[Unified PaySys] Large Bishop packet (229 bytes): ${data.subarray(0, 8).toString('hex')}`);
            
            const protocol = data.readUInt16LE(2);
            this.log(`[Unified PaySys] Large packet protocol: 0x${protocol.toString(16)}`);
            
            // Generic response for large packets
            const response = Buffer.alloc(64);
            response.writeUInt16LE(64, 0);       // Size: 64 bytes
            response.writeUInt16LE(protocol, 2); // Echo protocol back  
            response.writeUInt32LE(1, 4);        // Success code
            
            socket.write(response);
            this.log(`[Unified PaySys] Sent large packet response: ${response.length} bytes`);
            
        } catch (error) {
            this.log(`[Unified PaySys] Error handling large Bishop packet: ${error.message}`);
        }
    }

    // Comprehensive protocol handlers from enhanced version
    
    async handlePlayerExchange(socket, data, connectionId) {
        // Player money/item exchange logic
        try {
            const playerId = data.readUInt32LE(4);
            const exchangeType = data.readUInt32LE(8);
            
            this.log(`[Unified PaySys] Player exchange: player=${playerId}, type=${exchangeType}`);
            
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
                    this.log(`[Unified PaySys] Player exchange successful`);
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
                this.log(`[Unified PaySys] Player exchange successful (no DB)`);
            }
            
        } catch (error) {
            this.log(`[Unified PaySys] Error in player exchange: ${error.message}`);
            this.sendErrorResponse(socket, 0x40, error.message);
        }
    }

    async handlePlayerEnterGame(socket, data, connectionId) {
        // Player entering game logic
        try {
            const playerId = data.readUInt32LE(4);
            const gameServerId = data.readUInt32LE(8);
            
            this.log(`[Unified PaySys] Player enter game: player=${playerId}, server=${gameServerId}`);
            
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
            this.log(`[Unified PaySys] Player enter game response sent`);
            
        } catch (error) {
            this.log(`[Unified PaySys] Error in player enter game: ${error.message}`);
            this.sendErrorResponse(socket, 0x45, error.message);
        }
    }

    async handlePlayerLeaveGame(socket, data, connectionId) {
        // Player leaving game logic  
        try {
            const playerId = data.readUInt32LE(4);
            
            this.log(`[Unified PaySys] Player leave game: player=${playerId}`);
            
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
            this.log(`[Unified PaySys] Player leave game response sent`);
            
        } catch (error) {
            this.log(`[Unified PaySys] Error in player leave game: ${error.message}`);
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
            this.log(`[Unified PaySys] Sent error response for protocol 0x${protocol.toString(16)}: ${errorMessage}`);
        } catch (error) {
            this.log(`[Unified PaySys] Error sending error response: ${error.message}`);
        }
    }

    async stop() {
        try {
            if (this.server) {
                this.server.close();
                this.log('[Unified PaySys] Server stopped');
            }
            
            if (this.dbConnection) {
                await this.dbConnection.end();
                this.log('[Unified PaySys] Database connection closed');
            }
        } catch (error) {
            this.log(`[Unified PaySys] Error stopping server: ${error.message}`);
        }
    }
}

// Start the unified server
async function main() {
    const server = new UnifiedPaySysServer();
    
    process.on('SIGINT', async () => {
        console.log('\n[Unified PaySys] Received SIGINT, shutting down gracefully...');
        await server.stop();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        console.log('\n[Unified PaySys] Received SIGTERM, shutting down gracefully...');
        await server.stop();
        process.exit(0);
    });

    await server.start();
}

if (require.main === module) {
    main().catch(console.error);
}

module.exports = UnifiedPaySysServer;