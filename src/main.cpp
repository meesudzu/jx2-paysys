#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include "paysys_server.h"
#include "config_manager.h"
#include "database_manager.h"

int main(int argc, char* argv[]) {
    (void)argc; // Suppress unused parameter warning
    (void)argv; // Suppress unused parameter warning
    std::cout << "JX2 Payment System Server v1.0" << std::endl;
    
    try {
        // Load configuration
        ConfigManager config;
        if (!config.LoadConfig("paysys.ini")) {
            std::cerr << "Failed to load configuration file" << std::endl;
            return 1;
        }
        
        // Initialize database
        DatabaseManager db;
        if (!db.Initialize(config)) {
            std::cerr << "Warning: Failed to initialize database connection, running in test mode" << std::endl;
            // Continue without database for testing
        }
        
        // Create and start payment system server
        PaysysServer server(config, db);
        if (!server.Start()) {
            std::cerr << "Failed to start payment system server" << std::endl;
            return 1;
        }
        
        std::cout << "Payment system server started successfully" << std::endl;
        std::cout << "Listening on port " << config.GetPaysysPort() << std::endl;
        std::cout << "Press Ctrl+C to stop the server..." << std::endl;
        
        // Keep the server running
        while (server.IsRunning()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}