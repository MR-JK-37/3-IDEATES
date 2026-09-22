# cybershield-android/app/src/main/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.22.0)
project(cybershield-native)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -fvisibility=hidden")

# Find YARA library (must be pre-built or available in NDK)
find_package(yara QUIET)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# YARA wrapper library - optional, built only if YARA found
if(YARA_FOUND)
    add_library(yara-bridge SHARED
        yara_bridge.cpp
    )

    target_link_libraries(yara-bridge
        ${YARA_LIBRARIES}
        log
    )

    target_include_directories(yara-bridge
        PRIVATE ${YARA_INCLUDE_DIRS}
    )
else()
    message(WARNING "YARA not found - YARA scanning will be disabled")
    # Create a stub library
    add_library(yara-bridge SHARED
        yara_bridge_stub.cpp
    )
    target_link_libraries(yara-bridge log)
endif()

# Ensure libraries are exported properly for Kotlin JNI access
set_target_properties(yara-bridge PROPERTIES
    SOVERSION 1
    VERSION 1.0.0
)
