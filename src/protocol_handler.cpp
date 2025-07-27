#include "protocol_handler.h"
#include <iostream>
#include <cstring>
#include <arpa/inet.h>

ProtocolHandler::ProtocolHandler(const ConfigManager& config, DatabaseManager& db)
    : config_(config), db_(db) {
}

ProtocolHandler::~ProtocolHandler() {
}

std::vector<uint8_t> ProtocolHandler::ProcessMessage(const std::vector<uint8_t>& raw_data, const std::string& client_ip) {
    if (raw_data.empty()) {
        return {};
    }
    
    // Decrypt the message if needed
    std::vector<uint8_t> decrypted_data = DecryptMessage(raw_data);
    
    // Parse the protocol message
    ProtocolMessage message = ParseMessage(decrypted_data);
    
    std::vector<uint8_t> response;
    
    // Handle different message types
    switch (message.type) {
        case MessageType::BISHOP_LOGIN:
            response = HandleBishopLogin(message.data, client_ip);
            break;
        case MessageType::BISHOP_LOGOUT:
            response = HandleBishopLogout(message.data, client_ip);
            break;
        case MessageType::BISHOP_LOGIN_RECONNECT:
            response = HandleBishopLoginReconnect(message.data, client_ip);
            break;
        case MessageType::USER_LOGIN:
            response = HandleUserLogin(message.data, client_ip);
            break;
        case MessageType::USER_LOGOUT:
            response = HandleUserLogout(message.data, client_ip);
            break;
        case MessageType::USER_LOGIN_VERIFY:
            response = HandleUserLoginVerify(message.data, client_ip);
            break;
        case MessageType::USER_EXT_CHANGE:
            response = HandleUserExtChange(message.data, client_ip);
            break;
        case MessageType::USER_IB_BUY_ITEM:
            response = HandleUserIBBuyItem(message.data, client_ip);
            break;
        case MessageType::USER_IB_USE_ITEM:
            response = HandleUserIBUseItem(message.data, client_ip);
            break;
        case MessageType::PING:
            response = HandlePing(message.data, client_ip);
            break;
        default:
            std::cerr << "Unknown message type received from " << client_ip << std::endl;
            return {};
    }
    
    // Encrypt the response if needed
    return EncryptMessage(response);
}

ProtocolMessage ProtocolHandler::ParseMessage(const std::vector<uint8_t>& raw_data) {
    if (raw_data.size() < 4) {
        return ProtocolMessage();
    }
    
    // Extract message type (first 4 bytes, little endian)
    uint32_t type_value = ExtractUInt32(raw_data, 0);
    MessageType type = static_cast<MessageType>(type_value);
    
    // Extract payload (rest of the data)
    std::vector<uint8_t> payload(raw_data.begin() + 4, raw_data.end());
    
    return ProtocolMessage(type, payload);
}

std::vector<uint8_t> ProtocolHandler::CreateResponse(MessageType type, int result_code, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> response;
    
    // Add message type
    AppendUInt32(response, static_cast<uint32_t>(type));
    
    // Add result code
    AppendUInt32(response, static_cast<uint32_t>(result_code));
    
    // Add payload
    response.insert(response.end(), payload.begin(), payload.end());
    
    return response;
}

std::vector<uint8_t> ProtocolHandler::HandleBishopLogin(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "Bishop login request from " << client_ip << std::endl;
    
    // Extract username and password from data
    std::string username = ExtractString(data, 0, 32);
    std::string password = ExtractString(data, 32, 32);
    
    std::cout << "Bishop username: " << username << std::endl;
    
    int result_code = config_.GetBishopLoginResult();
    
    // Validate bishop credentials (simplified for now)
    if (username == "bishop" && password == "1234") {
        std::cout << "Bishop login successful" << std::endl;
    } else {
        std::cout << "Bishop login failed - invalid credentials" << std::endl;
        result_code = 0; // Failed
    }
    
    return CreateResponse(MessageType::BISHOP_LOGIN, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleBishopLogout(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "Bishop logout request from " << client_ip << std::endl;
    
    int result_code = config_.GetBishopLogoutResult();
    
    return CreateResponse(MessageType::BISHOP_LOGOUT, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleBishopLoginReconnect(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "Bishop login reconnect request from " << client_ip << std::endl;
    
    int result_code = config_.GetBishopLoginReconnectResult();
    
    return CreateResponse(MessageType::BISHOP_LOGIN_RECONNECT, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleUserLogin(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "User login request from " << client_ip << std::endl;
    
    // Extract username and password
    std::string username = ExtractString(data, 0, 32);
    std::string password = ExtractString(data, 32, 64);
    
    std::cout << "User login: " << username << std::endl;
    
    int result_code = config_.GetUserLoginResult();
    
    // Validate user credentials
    if (!db_.ValidatePassword(username, password)) {
        std::cout << "User login failed - invalid credentials" << std::endl;
        result_code = 0;
    } else if (db_.IsAccountLocked(username)) {
        std::cout << "User login failed - account locked" << std::endl;
        result_code = 0;
    } else {
        std::cout << "User login successful" << std::endl;
        // Update last login IP
        uint32_t ip = GetClientIP(client_ip);
        db_.UpdateLastLoginIP(username, ip);
    }
    
    return CreateResponse(MessageType::USER_LOGIN, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleUserLogout(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "User logout request from " << client_ip << std::endl;
    
    int result_code = config_.GetUserLogoutResult();
    
    return CreateResponse(MessageType::USER_LOGOUT, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleUserLoginVerify(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "User login verify request from " << client_ip << std::endl;
    
    int result_code = config_.GetUserLoginVerifyResult();
    
    return CreateResponse(MessageType::USER_LOGIN_VERIFY, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleUserExtChange(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "User ext change request from " << client_ip << std::endl;
    
    int result_code = config_.GetUserExtChangeResult();
    
    return CreateResponse(MessageType::USER_EXT_CHANGE, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleUserIBBuyItem(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "User IB buy item request from " << client_ip << std::endl;
    
    int result_code = config_.GetUserIBBuyItemResult();
    
    return CreateResponse(MessageType::USER_IB_BUY_ITEM, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandleUserIBUseItem(const std::vector<uint8_t>& data, const std::string& client_ip) {
    std::cout << "User IB use item request from " << client_ip << std::endl;
    
    int result_code = config_.GetUserIBUseItemResult();
    
    return CreateResponse(MessageType::USER_IB_USE_ITEM, result_code);
}

std::vector<uint8_t> ProtocolHandler::HandlePing(const std::vector<uint8_t>& data, const std::string& client_ip) {
    // Ping - just echo back
    return CreateResponse(MessageType::PING, 1);
}

// Utility functions
std::string ProtocolHandler::ExtractString(const std::vector<uint8_t>& data, size_t offset, size_t max_length) {
    if (offset >= data.size()) {
        return "";
    }
    
    size_t end_pos = data.size();
    if (max_length > 0) {
        end_pos = std::min(offset + max_length, data.size());
    }
    
    // Find null terminator
    for (size_t i = offset; i < end_pos; ++i) {
        if (data[i] == 0) {
            end_pos = i;
            break;
        }
    }
    
    return std::string(reinterpret_cast<const char*>(data.data() + offset), end_pos - offset);
}

uint32_t ProtocolHandler::ExtractUInt32(const std::vector<uint8_t>& data, size_t offset) {
    if (offset + 4 > data.size()) {
        return 0;
    }
    
    uint32_t value;
    memcpy(&value, data.data() + offset, 4);
    return value; // Assuming little endian
}

void ProtocolHandler::AppendUInt32(std::vector<uint8_t>& data, uint32_t value) {
    uint8_t bytes[4];
    memcpy(bytes, &value, 4);
    data.insert(data.end(), bytes, bytes + 4);
}

void ProtocolHandler::AppendString(std::vector<uint8_t>& data, const std::string& str, size_t fixed_length) {
    if (fixed_length > 0) {
        std::vector<uint8_t> padded(fixed_length, 0);
        size_t copy_length = std::min(str.length(), fixed_length - 1);
        memcpy(padded.data(), str.c_str(), copy_length);
        data.insert(data.end(), padded.begin(), padded.end());
    } else {
        data.insert(data.end(), str.begin(), str.end());
        data.push_back(0); // Null terminator
    }
}

uint32_t ProtocolHandler::GetClientIP(const std::string& client_ip) {
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, client_ip.c_str(), &(sa.sin_addr));
    if (result != 1) {
        return 0;
    }
    return ntohl(sa.sin_addr.s_addr);
}

// Simple XOR encryption for now (based on typical game server patterns)
std::vector<uint8_t> ProtocolHandler::DecryptMessage(const std::vector<uint8_t>& encrypted_data) {
    // For now, assume no encryption or simple XOR
    // This would need to be implemented based on reverse engineering of the original
    return encrypted_data;
}

std::vector<uint8_t> ProtocolHandler::EncryptMessage(const std::vector<uint8_t>& plain_data) {
    // For now, assume no encryption or simple XOR
    // This would need to be implemented based on reverse engineering of the original
    return plain_data;
}