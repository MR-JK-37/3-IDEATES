cmake_minimum_required(VERSION 3.10)
project(AVFilter)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_VERSION 10.0)

# Windows Driver Kit paths (adjust for your WDK installation)
set(WDK_PATH "C:/Program Files (x86)/Windows Kits/10" CACHE PATH "Windows Driver Kit path")
set(WDK_VERSION "10.0.22621.0" CACHE STRING "WDK Version")

# Compiler settings for kernel driver
set(CMAKE_C_COMPILER_ID MSVC)
set(CMAKE_CXX_COMPILER_ID MSVC)

# Add kernel mode compilation flags
add_compile_definitions(
    DRIVER
    __KERNEL__
    NTDDI_VERSION=0x0A000007  # NTDDI_WIN10_FE
    _KERNEL_MODE
)

# Include directories
include_directories(
    "${WDK_PATH}/Include/${WDK_VERSION}/km"
    "${WDK_PATH}/Include/${WDK_VERSION}/shared"
    "${WDK_PATH}/Include/${WDK_VERSION}/um"
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Library directories
link_directories(
    "${WDK_PATH}/Lib/${WDK_VERSION}/km/x64"
)

# Driver target
add_library(minifilter MODULE
    minifilter.c
    minifilter.h
)

# Required kernel driver libraries
target_link_libraries(minifilter
    fltmgr.lib
    ntoskrnl.lib
    wdmsec.lib
)

# Set output as .sys (kernel driver)
set_target_properties(minifilter PROPERTIES
    SUFFIX ".sys"
    PREFIX ""
)

# Compiler flags for kernel
if(MSVC)
    target_compile_options(minifilter PRIVATE
        /kernel
        /O2
        /W4
        /WX
        /GR-
        /GS-
        /fp:precise
    )
    
    target_link_options(minifilter PRIVATE
        /KERNEL
        /SUBSYSTEM:NATIVE
    )
endif()

# Installation targets
install(TARGETS minifilter
    LIBRARY DESTINATION drivers
    RUNTIME DESTINATION drivers
)

install(FILES minifilter.inf
    DESTINATION drivers
)
