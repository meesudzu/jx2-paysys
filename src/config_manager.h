#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <string>
#include <unordered_map>

class ConfigManager {
public:
    ConfigManager();
    ~ConfigManager();
    
    bool LoadConfig(const std::string& filename);
    
    // Paysys configuration
    std::string GetPaysysIP() const;
    int GetPaysysPort() const;
    int GetMaxAcceptEachWait() const;
    int GetMaxRecvBufSizePerSocket() const;
    int GetMaxSendBufSizePerSocket() const;
    int GetMaxEventCount() const;
    
    // Database configuration
    std::string GetDatabaseHost() const;
    std::string GetDatabaseUsername() const;
    std::string GetDatabasePassword() const;
    std::string GetDatabaseName() const;
    
    // Return codes configuration
    int GetBishopLoginResult() const;
    int GetBishopLoginReconnectResult() const;
    int GetBishopLogoutResult() const;
    int GetUserLoginResult() const;
    int GetUserLogoutResult() const;
    int GetUserLoginVerifyResult() const;
    int GetUserExtChangeResult() const;
    int GetUserIBBuyItemResult() const;
    int GetUserIBUseItemResult() const;
    
private:
    std::unordered_map<std::string, std::string> config_values_;
    
    std::string GetValue(const std::string& key, const std::string& default_value = "") const;
    int GetIntValue(const std::string& key, int default_value = 0) const;
    bool ParseIniFile(const std::string& filename);
};

#endif // CONFIG_MANAGER_H