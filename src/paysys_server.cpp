#include "paysys_server.h"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>

// ClientConnection implementation
ClientConnection::ClientConnection(int socket, const sockaddr_in& address) 
    : socket_(socket), connected_(true) {
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &address.sin_addr, ip_str, INET_ADDRSTRLEN);
    ip_address_ = std::string(ip_str);
}

ClientConnection::~ClientConnection() {
    if (socket_ >= 0) {
        close(socket_);
    }
}

bool ClientConnection::SendData(const std::vector<uint8_t>& data) {
    if (!connected_ || socket_ < 0) {
        return false;
    }
    
    size_t total_sent = 0;
    while (total_sent < data.size()) {
        ssize_t sent = send(socket_, 
                           reinterpret_cast<const char*>(data.data()) + total_sent, 
                           data.size() - total_sent, 
                           MSG_NOSIGNAL);
        
        if (sent <= 0) {
            connected_ = false;
            return false;
        }
        total_sent += sent;
    }
    
    return true;
}

std::vector<uint8_t> ClientConnection::ReceiveData() {
    std::vector<uint8_t> buffer(4096);
    
    if (!connected_ || socket_ < 0) {
        return std::vector<uint8_t>();
    }
    
    ssize_t received = recv(socket_, 
                           reinterpret_cast<char*>(buffer.data()), 
                           buffer.size(), 
                           0);
    
    if (received <= 0) {
        connected_ = false;
        return std::vector<uint8_t>();
    }
    
    buffer.resize(received);
    return buffer;
}

// PaysysServer implementation
PaysysServer::PaysysServer(const ConfigManager& config, DatabaseManager& db)
    : config_(config), db_(db), protocol_handler_(config, db), 
      running_(false), server_socket_(-1) {
}

PaysysServer::~PaysysServer() {
    Stop();
}

bool PaysysServer::Start() {
    if (running_) {
        return true;
    }
    
    if (!CreateServerSocket()) {
        return false;
    }
    
    running_ = true;
    accept_thread_ = std::thread(&PaysysServer::AcceptClients, this);
    
    std::cout << "Payment system server started on " 
              << config_.GetPaysysIP() << ":" << config_.GetPaysysPort() << std::endl;
    
    return true;
}

void PaysysServer::Stop() {
    if (!running_) {
        return;
    }
    
    running_ = false;
    
    CloseServerSocket();
    
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
    
    // Stop all client threads
    for (auto& thread : client_threads_) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    client_threads_.clear();
    
    // Clean up client connections
    client_connections_.clear();
    
    std::cout << "Payment system server stopped" << std::endl;
}

bool PaysysServer::CreateServerSocket() {
    server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket_ < 0) {
        std::cerr << "Failed to create server socket" << std::endl;
        return false;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        std::cerr << "Failed to set socket options" << std::endl;
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }
    
    // Bind socket
    sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config_.GetPaysysPort());
    
    std::string bind_ip = config_.GetPaysysIP();
    if (bind_ip.empty() || bind_ip == "127.0.0.1") {
        server_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, bind_ip.c_str(), &server_addr.sin_addr) <= 0) {
            std::cerr << "Invalid bind IP address: " << bind_ip << std::endl;
            close(server_socket_);
            server_socket_ = -1;
            return false;
        }
    }
    
    if (bind(server_socket_, reinterpret_cast<sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
        std::cerr << "Failed to bind socket to port " << config_.GetPaysysPort() << std::endl;
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }
    
    // Listen for connections
    if (listen(server_socket_, config_.GetMaxAcceptEachWait()) < 0) {
        std::cerr << "Failed to listen on socket" << std::endl;
        close(server_socket_);
        server_socket_ = -1;
        return false;
    }
    
    return true;
}

void PaysysServer::CloseServerSocket() {
    if (server_socket_ >= 0) {
        close(server_socket_);
        server_socket_ = -1;
    }
}

void PaysysServer::AcceptClients() {
    while (running_) {
        sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket_, 
                                  reinterpret_cast<sockaddr*>(&client_addr), 
                                  &client_addr_len);
        
        if (client_socket < 0) {
            if (running_) {
                std::cerr << "Failed to accept client connection" << std::endl;
            }
            continue;
        }
        
        // Create client connection
        std::unique_ptr<ClientConnection> client(new ClientConnection(client_socket, client_addr));
        std::cout << "New client connected from " << client->GetIPAddress() << std::endl;
        
        // Start client handler thread
        client_threads_.emplace_back(&PaysysServer::HandleClient, this, std::move(client));
        
        // Clean up disconnected clients periodically
        CleanupDisconnectedClients();
    }
}

void PaysysServer::HandleClient(std::unique_ptr<ClientConnection> client) {
    // Send initial security handshake/greeting to client immediately upon connection
    // The Bishop client expects to receive this first (_RecvSecurityKey)
    // Let's try a simple 4-byte acknowledgment that's common in JX2 servers
    std::vector<uint8_t> security_ack = {0x00, 0x00, 0x00, 0x01}; // Simple "OK" response
    
    if (!client->SendData(security_ack)) {
        std::cerr << "Failed to send security ack to client " << client->GetIPAddress() << std::endl;
        return;
    }
    std::cout << "Sent security ack to client " << client->GetIPAddress() << std::endl;
    
    std::cout << "Client " << client->GetIPAddress() << " connected, waiting for data..." << std::endl;
    
    while (running_ && client->IsConnected()) {
        // Receive data from client
        std::vector<uint8_t> received_data = client->ReceiveData();
        
        if (received_data.empty()) {
            // Client disconnected or error
            break;
        }
        
        // Log the received data for debugging
        std::cout << "Received " << received_data.size() << " bytes from " << client->GetIPAddress() << std::endl;
        std::cout << "Data: ";
        for (size_t i = 0; i < std::min(received_data.size(), static_cast<size_t>(32)); ++i) {
            printf("%02x ", received_data[i]);
        }
        std::cout << std::endl;
        
        // Process the received data through protocol handler
        std::vector<uint8_t> response = protocol_handler_.ProcessMessage(received_data, client->GetIPAddress());
        
        // Send response back to client
        if (!response.empty()) {
            if (!client->SendData(response)) {
                std::cerr << "Failed to send response to client " << client->GetIPAddress() << std::endl;
                break;
            }
        }
    }
    
    std::cout << "Client " << client->GetIPAddress() << " disconnected" << std::endl;
    client->SetDisconnected();
}

void PaysysServer::CleanupDisconnectedClients() {
    // Remove finished threads
    client_threads_.erase(
        std::remove_if(client_threads_.begin(), client_threads_.end(),
                      [](std::thread& t) {
                          if (t.joinable()) {
                              return false;
                          }
                          return true;
                      }),
        client_threads_.end());
}