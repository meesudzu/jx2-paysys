#ifndef PAYSYS_SERVER_H
#define PAYSYS_SERVER_H

#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <memory>
#include <sys/socket.h>
#include <netinet/in.h>
#include "config_manager.h"
#include "database_manager.h"
#include "protocol_handler.h"

class ClientConnection {
public:
    ClientConnection(int socket, const sockaddr_in& address);
    ~ClientConnection();
    
    int GetSocket() const { return socket_; }
    std::string GetIPAddress() const { return ip_address_; }
    bool IsConnected() const { return connected_; }
    void SetDisconnected() { connected_ = false; }
    
    bool SendData(const std::vector<uint8_t>& data);
    std::vector<uint8_t> ReceiveData();
    
private:
    int socket_;
    std::string ip_address_;
    std::atomic<bool> connected_;
};

class PaysysServer {
public:
    PaysysServer(const ConfigManager& config, DatabaseManager& db);
    ~PaysysServer();
    
    bool Start();
    void Stop();
    bool IsRunning() const { return running_; }
    
private:
    const ConfigManager& config_;
    DatabaseManager& db_;
    ProtocolHandler protocol_handler_;
    
    std::atomic<bool> running_;
    int server_socket_;
    std::thread accept_thread_;
    std::vector<std::thread> client_threads_;
    std::vector<std::unique_ptr<ClientConnection>> client_connections_;
    
    void AcceptClients();
    void HandleClient(std::unique_ptr<ClientConnection> client);
    void CleanupDisconnectedClients();
    
    bool CreateServerSocket();
    void CloseServerSocket();
};

#endif // PAYSYS_SERVER_H