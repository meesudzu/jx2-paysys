#include "config_manager.h"
#include <fstream>
#include <sstream>
#include <iostream>

ConfigManager::ConfigManager() {
    // Set default values
    config_values_["szPaysysIPAddress"] = "127.0.0.1";
    config_values_["nPaysysPort"] = "8000";
    config_values_["nMaxAcceptEachWait"] = "512";
    config_values_["nMaxRecvBufSizePerSocket"] = "2048";
    config_values_["nMaxSendBufSizePerSocket"] = "2048";
    config_values_["nMaxEventCount"] = "512";
    
    config_values_["Host"] = "127.0.0.1";
    config_values_["Username"] = "root";
    config_values_["Password"] = "1234";
    config_values_["DBName"] = "jx2_paysys";
    
    config_values_["nBishopLoginResult"] = "1";
    config_values_["nBishopLoginReconnectResult"] = "1";
    config_values_["nBishopLogoutResult"] = "1";
    config_values_["nUserLoginResult"] = "1";
    config_values_["nUserLogoutResult"] = "1";
    config_values_["nUserLoginVerifyResult"] = "1";
    config_values_["nUserExtChangeResult"] = "1";
    config_values_["nUserIBBuyItemResult"] = "1";
    config_values_["nUserIBUseItemResult"] = "1";
}

ConfigManager::~ConfigManager() {
}

bool ConfigManager::LoadConfig(const std::string& filename) {
    return ParseIniFile(filename);
}

bool ConfigManager::ParseIniFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Cannot open config file: " << filename << std::endl;
        return false;
    }
    
    std::string line;
    std::string current_section;
    
    while (std::getline(file, line)) {
        // Remove leading/trailing whitespace
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Check for section header
        if (line[0] == '[' && line.back() == ']') {
            current_section = line.substr(1, line.length() - 2);
            continue;
        }
        
        // Parse key=value pairs
        size_t eq_pos = line.find('=');
        if (eq_pos != std::string::npos) {
            std::string key = line.substr(0, eq_pos);
            std::string value = line.substr(eq_pos + 1);
            
            // Remove whitespace around key and value
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config_values_[key] = value;
        }
    }
    
    return true;
}

std::string ConfigManager::GetValue(const std::string& key, const std::string& default_value) const {
    auto it = config_values_.find(key);
    return (it != config_values_.end()) ? it->second : default_value;
}

int ConfigManager::GetIntValue(const std::string& key, int default_value) const {
    std::string value = GetValue(key);
    if (value.empty()) {
        return default_value;
    }
    
    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        return default_value;
    }
}

std::string ConfigManager::GetPaysysIP() const {
    std::string ip = GetValue("szPaysysIPAddress");
    return ip.empty() ? "127.0.0.1" : ip;
}

int ConfigManager::GetPaysysPort() const {
    return GetIntValue("nPaysysPort", 8000);
}

int ConfigManager::GetMaxAcceptEachWait() const {
    return GetIntValue("nMaxAcceptEachWait", 512);
}

int ConfigManager::GetMaxRecvBufSizePerSocket() const {
    return GetIntValue("nMaxRecvBufSizePerSocket", 2048);
}

int ConfigManager::GetMaxSendBufSizePerSocket() const {
    return GetIntValue("nMaxSendBufSizePerSocket", 2048);
}

int ConfigManager::GetMaxEventCount() const {
    return GetIntValue("nMaxEventCount", 512);
}

std::string ConfigManager::GetDatabaseHost() const {
    return GetValue("Host", "127.0.0.1");
}

std::string ConfigManager::GetDatabaseUsername() const {
    return GetValue("Username", "root");
}

std::string ConfigManager::GetDatabasePassword() const {
    return GetValue("Password", "1234");
}

std::string ConfigManager::GetDatabaseName() const {
    return GetValue("DBName", "jx2_paysys");
}

int ConfigManager::GetBishopLoginResult() const {
    return GetIntValue("nBishopLoginResult", 1);
}

int ConfigManager::GetBishopLoginReconnectResult() const {
    return GetIntValue("nBishopLoginReconnectResult", 1);
}

int ConfigManager::GetBishopLogoutResult() const {
    return GetIntValue("nBishopLogoutResult", 1);
}

int ConfigManager::GetUserLoginResult() const {
    return GetIntValue("nUserLoginResult", 1);
}

int ConfigManager::GetUserLogoutResult() const {
    return GetIntValue("nUserLogoutResult", 1);
}

int ConfigManager::GetUserLoginVerifyResult() const {
    return GetIntValue("nUserLoginVerifyResult", 1);
}

int ConfigManager::GetUserExtChangeResult() const {
    return GetIntValue("nUserExtChangeResult", 1);
}

int ConfigManager::GetUserIBBuyItemResult() const {
    return GetIntValue("nUserIBBuyItemResult", 1);
}

int ConfigManager::GetUserIBUseItemResult() const {
    return GetIntValue("nUserIBUseItemResult", 1);
}