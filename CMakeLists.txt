cmake_minimum_required(VERSION 3.12)
project(cyberhaven-guardian CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(USE_LIBCURL "Enable webhook notifications via libcurl" ON)

add_executable(cyberhaven-guardian src/cyberhaven.cpp)

find_package(Threads REQUIRED)

# libpcap
find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
find_library(PCAP_LIBRARY pcap)
if (NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR "libpcap not found")
endif()
target_include_directories(cyberhaven-guardian PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(cyberhaven-guardian PRIVATE ${PCAP_LIBRARY})

# OpenSSL (for MD5 used in JA3 hashing scaffolding)
find_package(OpenSSL REQUIRED)
target_link_libraries(cyberhaven-guardian PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# libcurl (optional but ON by default)
if (USE_LIBCURL)
  find_package(CURL REQUIRED)
  target_compile_definitions(cyberhaven-guardian PRIVATE USE_LIBCURL)
  target_link_libraries(cyberhaven-guardian PRIVATE CURL::libcurl)
endif()

target_link_libraries(cyberhaven-guardian PRIVATE Threads::Threads)


