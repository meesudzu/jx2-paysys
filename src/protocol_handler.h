#ifndef PROTOCOL_HANDLER_H
#define PROTOCOL_HANDLER_H

#include <vector>
#include <string>
#include <cstdint>
#include "config_manager.h"
#include "database_manager.h"

// JX2 Payment Protocol Message Types
enum class MessageType : uint32_t {
    BISHOP_LOGIN = 0x01,
    BISHOP_LOGOUT = 0x02,
    BISHOP_LOGIN_RECONNECT = 0x03,
    USER_LOGIN = 0x10,
    USER_LOGOUT = 0x11,
    USER_LOGIN_VERIFY = 0x12,
    USER_EXT_CHANGE = 0x20,
    USER_IB_BUY_ITEM = 0x30,
    USER_IB_USE_ITEM = 0x31,
    PING = 0xFF,
    UNKNOWN = 0x00
};

struct ProtocolMessage {
    MessageType type;
    std::vector<uint8_t> data;
    
    ProtocolMessage() : type(MessageType::UNKNOWN) {}
    ProtocolMessage(MessageType t, const std::vector<uint8_t>& d) : type(t), data(d) {}
};

class ProtocolHandler {
public:
    ProtocolHandler(const ConfigManager& config, DatabaseManager& db);
    ~ProtocolHandler();
    
    std::vector<uint8_t> ProcessMessage(const std::vector<uint8_t>& raw_data, const std::string& client_ip);
    
private:
    const ConfigManager& config_;
    DatabaseManager& db_;
    
    // Protocol parsing
    ProtocolMessage ParseMessage(const std::vector<uint8_t>& raw_data);
    std::vector<uint8_t> CreateResponse(MessageType type, int result_code, const std::vector<uint8_t>& payload = {});
    
    // Message handlers
    std::vector<uint8_t> HandleBishopLogin(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleBishopLogout(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleBishopLoginReconnect(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleUserLogin(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleUserLogout(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleUserLoginVerify(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleUserExtChange(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleUserIBBuyItem(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandleUserIBUseItem(const std::vector<uint8_t>& data, const std::string& client_ip);
    std::vector<uint8_t> HandlePing(const std::vector<uint8_t>& data, const std::string& client_ip);
    
    // Utility functions
    std::string ExtractString(const std::vector<uint8_t>& data, size_t offset, size_t max_length = 0);
    uint32_t ExtractUInt32(const std::vector<uint8_t>& data, size_t offset);
    void AppendUInt32(std::vector<uint8_t>& data, uint32_t value);
    void AppendString(std::vector<uint8_t>& data, const std::string& str, size_t fixed_length = 0);
    uint32_t GetClientIP(const std::string& client_ip);
    
    // Encryption/Decryption (based on reverse engineering)
    std::vector<uint8_t> DecryptMessage(const std::vector<uint8_t>& encrypted_data);
    std::vector<uint8_t> EncryptMessage(const std::vector<uint8_t>& plain_data);
};

#endif // PROTOCOL_HANDLER_H