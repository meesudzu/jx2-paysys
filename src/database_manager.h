#ifndef DATABASE_MANAGER_H
#define DATABASE_MANAGER_H

#include <string>
#include <memory>
#ifndef NO_DATABASE
#include <mysql/mysql.h>
#endif
#include "config_manager.h"

struct AccountInfo {
    int id;
    std::string username;
    std::string password;
    std::string secpassword;
    std::string rowpass;
    int active;
    int locked;
    int coin;
    int testcoin;
    int lockedCoin;
    std::string email;
    int cmnd;
    int LastLoginIP;
    // Additional fields as needed
};

class DatabaseManager {
public:
    DatabaseManager();
    ~DatabaseManager();
    
    bool Initialize(const ConfigManager& config);
    void Cleanup();
    
    // Account operations
    bool GetAccountInfo(const std::string& username, AccountInfo& account);
    bool ValidatePassword(const std::string& username, const std::string& password);
    bool UpdateLastLoginIP(const std::string& username, int ip);
    bool IsAccountLocked(const std::string& username);
    bool UpdateAccountCoins(const std::string& username, int coins);
    
    // Connection management
    bool IsConnected() const;
    bool Reconnect();
    
private:
#ifndef NO_DATABASE
    MYSQL* mysql_connection_;
#endif
    std::string host_;
    std::string username_;
    std::string password_;
    std::string database_;
    
    bool ExecuteQuery(const std::string& query);
#ifndef NO_DATABASE
    MYSQL_RES* ExecuteSelectQuery(const std::string& query);
#endif
    std::string EscapeString(const std::string& input);
};

#endif // DATABASE_MANAGER_H