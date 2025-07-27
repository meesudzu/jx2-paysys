cmake_minimum_required(VERSION 3.10)
project(JX2PaySys)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add compile flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2")

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(MYSQL REQUIRED mysqlclient)

find_package(Threads REQUIRED)

# Include directories
include_directories(${MYSQL_INCLUDE_DIRS})

# Source files
set(SOURCES
    src/main.cpp
    src/config_manager.cpp
    src/database_manager.cpp
    src/paysys_server.cpp
    src/protocol_handler.cpp
)

# Create executable
add_executable(paysys ${SOURCES})

# Link libraries
target_link_libraries(paysys 
    ${MYSQL_LIBRARIES}
    Threads::Threads
)

# Set output directory
set_target_properties(paysys PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Install target
install(TARGETS paysys DESTINATION bin)
install(FILES paysys.ini DESTINATION bin)