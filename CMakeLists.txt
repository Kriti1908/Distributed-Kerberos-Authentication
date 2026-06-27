cmake_minimum_required(VERSION 3.16)
project(SNS_A3_ThresholdKerberos CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─── Compiler flags ────────────────────────────────────────────────────────────
if(MSVC)
    add_compile_options(/W4 /O2)
    # Suppress overly verbose MSVC warnings
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

# ─── Platform-specific libraries ───────────────────────────────────────────────
if(WIN32)
    set(PLATFORM_LIBS ws2_32 bcrypt)
else()
    find_package(Threads REQUIRED)
    set(PLATFORM_LIBS pthread)
endif()

# ─── Shared library: crypto + network core ─────────────────────────────────────
add_library(kerberos_core STATIC
    src/bigint.cpp
    src/crypto_utils.cpp
    src/schnorr.cpp
    src/ticket.cpp
    src/network.cpp
)

target_include_directories(kerberos_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kerberos_core PUBLIC ${PLATFORM_LIBS})

if(NOT WIN32)
    target_link_libraries(kerberos_core PUBLIC Threads::Threads)
endif()

# ─── Executables ───────────────────────────────────────────────────────────────
add_executable(master_keygen master_keygen.cpp)
target_link_libraries(master_keygen PRIVATE kerberos_core)

add_executable(as_node as_node.cpp)
target_link_libraries(as_node PRIVATE kerberos_core)

add_executable(tgs_node tgs_node.cpp)
target_link_libraries(tgs_node PRIVATE kerberos_core)

add_executable(service_server service_server.cpp)
target_link_libraries(service_server PRIVATE kerberos_core)

add_executable(client client.cpp)
target_link_libraries(client PRIVATE kerberos_core)

add_executable(attacks attacks.cpp)
target_link_libraries(attacks PRIVATE kerberos_core)

# ─── Install targets ───────────────────────────────────────────────────────────
install(TARGETS
    master_keygen as_node tgs_node service_server client attacks
    RUNTIME DESTINATION bin
)
