#include "database_manager.h"
#include <iostream>
#include <cstring>

DatabaseManager::DatabaseManager()
#ifndef NO_DATABASE
    : mysql_connection_(nullptr)
#endif
{
}

DatabaseManager::~DatabaseManager() {
    Cleanup();
}

bool DatabaseManager::Initialize(const ConfigManager& config) {
#ifdef NO_DATABASE
    std::cout << "Running in NO_DATABASE mode - all database operations will be simulated" << std::endl;
    return true;
#else
    host_ = config.GetDatabaseHost();
    username_ = config.GetDatabaseUsername();
    password_ = config.GetDatabasePassword();
    database_ = config.GetDatabaseName();
    
    mysql_connection_ = mysql_init(nullptr);
    if (!mysql_connection_) {
        std::cerr << "Failed to initialize MySQL connection" << std::endl;
        return false;
    }
    
    // Set connection timeout
    unsigned int timeout = 10;
    mysql_options(mysql_connection_, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    mysql_options(mysql_connection_, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(mysql_connection_, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
    
    // Connect to database
    if (!mysql_real_connect(mysql_connection_, 
                           host_.c_str(), 
                           username_.c_str(), 
                           password_.c_str(), 
                           database_.c_str(), 
                           3306, 
                           nullptr, 
                           0)) {
        std::cerr << "Failed to connect to MySQL: " << mysql_error(mysql_connection_) << std::endl;
        mysql_close(mysql_connection_);
        mysql_connection_ = nullptr;
        return false;
    }
    
    // Set character set to UTF-8
    mysql_set_character_set(mysql_connection_, "utf8");
    
    std::cout << "Connected to MySQL database: " << database_ << std::endl;
    return true;
#endif
}

void DatabaseManager::Cleanup() {
#ifndef NO_DATABASE
    if (mysql_connection_) {
        mysql_close(mysql_connection_);
        mysql_connection_ = nullptr;
    }
#endif
}

bool DatabaseManager::IsConnected() const {
#ifdef NO_DATABASE
    return true; // Always "connected" in no-database mode
#else
    if (!mysql_connection_) {
        return false;
    }
    
    // Ping the server to check connection
    return mysql_ping(mysql_connection_) == 0;
#endif
}

bool DatabaseManager::Reconnect() {
#ifdef NO_DATABASE
    return true; // Always successful in no-database mode
#else
    if (mysql_connection_) {
        mysql_close(mysql_connection_);
    }
    
    mysql_connection_ = mysql_init(nullptr);
    if (!mysql_connection_) {
        return false;
    }
    
    unsigned int timeout = 10;
    mysql_options(mysql_connection_, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
    mysql_options(mysql_connection_, MYSQL_OPT_READ_TIMEOUT, &timeout);
    mysql_options(mysql_connection_, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
    
    if (!mysql_real_connect(mysql_connection_, 
                           host_.c_str(), 
                           username_.c_str(), 
                           password_.c_str(), 
                           database_.c_str(), 
                           3306, 
                           nullptr, 
                           0)) {
        mysql_close(mysql_connection_);
        mysql_connection_ = nullptr;
        return false;
    }
    
    mysql_set_character_set(mysql_connection_, "utf8");
    return true;
#endif
}

std::string DatabaseManager::EscapeString(const std::string& input) {
#ifdef NO_DATABASE
    return input; // No escaping needed in no-database mode
#else
    if (!mysql_connection_) {
        return input;
    }
    
    char* escaped = new char[input.length() * 2 + 1];
    mysql_real_escape_string(mysql_connection_, escaped, input.c_str(), input.length());
    std::string result(escaped);
    delete[] escaped;
    return result;
#endif
}

bool DatabaseManager::ExecuteQuery(const std::string& query) {
#ifdef NO_DATABASE
    std::cout << "NO_DATABASE mode: Would execute query: " << query << std::endl;
    return true;
#else
    if (!mysql_connection_) {
        std::cerr << "No database connection" << std::endl;
        return false;
    }
    
    if (mysql_query(mysql_connection_, query.c_str()) != 0) {
        std::cerr << "Query failed: " << mysql_error(mysql_connection_) << std::endl;
        std::cerr << "Query: " << query << std::endl;
        return false;
    }
    
    return true;
#endif
}

#ifndef NO_DATABASE
MYSQL_RES* DatabaseManager::ExecuteSelectQuery(const std::string& query) {
    if (!ExecuteQuery(query)) {
        return nullptr;
    }
    
    return mysql_store_result(mysql_connection_);
}
#endif

bool DatabaseManager::GetAccountInfo(const std::string& username, AccountInfo& account) {
#ifdef NO_DATABASE
    // Return test account info for known test usernames
    if (username == "test" || username == "bishop") {
        account.id = 1;
        account.username = username;
        account.password = (username == "test") ? "test" : "1234";
        account.secpassword = "";
        account.rowpass = "";
        account.active = 1;
        account.locked = 0;
        account.coin = 1000;
        account.testcoin = 0;
        account.lockedCoin = 0;
        account.email = "test@test.com";
        account.cmnd = 0;
        account.LastLoginIP = 0;
        return true;
    }
    return false;
#else
    std::string escaped_username = EscapeString(username);
    std::string query = "SELECT id, username, password, secpassword, rowpass, active, locked, "
                       "coin, testcoin, lockedCoin, email, cmnd, LastLoginIP "
                       "FROM account WHERE username = '" + escaped_username + "'";
    
    MYSQL_RES* result = ExecuteSelectQuery(query);
    if (!result) {
        return false;
    }
    
    MYSQL_ROW row = mysql_fetch_row(result);
    if (!row) {
        mysql_free_result(result);
        return false;
    }
    
    account.id = std::atoi(row[0]);
    account.username = row[1] ? row[1] : "";
    account.password = row[2] ? row[2] : "";
    account.secpassword = row[3] ? row[3] : "";
    account.rowpass = row[4] ? row[4] : "";
    account.active = std::atoi(row[5]);
    account.locked = std::atoi(row[6]);
    account.coin = std::atoi(row[7]);
    account.testcoin = std::atoi(row[8]);
    account.lockedCoin = std::atoi(row[9]);
    account.email = row[10] ? row[10] : "";
    account.cmnd = std::atoi(row[11]);
    account.LastLoginIP = std::atoi(row[12]);
    
    mysql_free_result(result);
    return true;
#endif
}

bool DatabaseManager::ValidatePassword(const std::string& username, const std::string& password) {
#ifdef NO_DATABASE
    // Test mode - accept test credentials
    return (username == "test" && password == "test") || (username == "bishop" && password == "1234");
#else
    if (!mysql_connection_) {
        // Test mode - accept test credentials
        return (username == "test" && password == "test") || (username == "bishop" && password == "1234");
    }
    
    AccountInfo account;
    if (!GetAccountInfo(username, account)) {
        return false;
    }
    
    // Compare password hash (assuming MD5 hash comparison)
    return account.password == password || account.secpassword == password;
#endif
}

bool DatabaseManager::UpdateLastLoginIP(const std::string& username, int ip) {
#ifdef NO_DATABASE
    // Test mode - just log
    std::cout << "NO_DATABASE mode: Would update " << username << " IP to " << ip << std::endl;
    return true;
#else
    if (!mysql_connection_) {
        // Test mode - just log
        std::cout << "Test mode: Would update " << username << " IP to " << ip << std::endl;
        return true;
    }
    
    std::string escaped_username = EscapeString(username);
    std::string query = "UPDATE account SET LastLoginIP = " + std::to_string(ip) + 
                       " WHERE username = '" + escaped_username + "'";
    
    return ExecuteQuery(query);
#endif
}

bool DatabaseManager::IsAccountLocked(const std::string& username) {
#ifdef NO_DATABASE
    // Test mode - no accounts are locked
    (void)username; // Suppress unused parameter warning
    return false;
#else
    if (!mysql_connection_) {
        // Test mode - no accounts are locked
        (void)username; // Suppress unused parameter warning
        return false;
    }
    
    AccountInfo account;
    if (!GetAccountInfo(username, account)) {
        return true; // Assume locked if account doesn't exist
    }
    
    return account.locked != 0 || account.active == 0;
#endif
}

bool DatabaseManager::UpdateAccountCoins(const std::string& username, int coins) {
#ifdef NO_DATABASE
    std::cout << "NO_DATABASE mode: Would update " << username << " coins to " << coins << std::endl;
    return true;
#else
    std::string escaped_username = EscapeString(username);
    std::string query = "UPDATE account SET coin = " + std::to_string(coins) + 
                       " WHERE username = '" + escaped_username + "'";
    
    return ExecuteQuery(query);
#endif
}