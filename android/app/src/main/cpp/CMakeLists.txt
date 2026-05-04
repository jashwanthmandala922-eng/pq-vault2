cmake_minimum_required(VERSION 3.22.1)
project("pqvault_core")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Add liboqs (if available)
# find_package(liboqs REQUIRED)

add_library(${CMAKE_PROJECT_NAME} SHARED
    pqvault_jni.cpp
)

# Link necessary libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    log
    android
)

# Include directories
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Build configuration for size
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")