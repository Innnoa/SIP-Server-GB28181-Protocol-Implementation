cmake_minimum_required(VERSION 3.10.2)
project(sipserver)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -pthread -Wno-deprecated-declarations")
set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "$ENV{CXXFLAGS} -O3 -Wall")

message(STATUS "CMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}")

# 查找 libcurl
find_package(PkgConfig REQUIRED)
pkg_check_modules(CURL REQUIRED libcurl)
if(CURL_FOUND)
    message(STATUS "Found libcurl: ${CURL_VERSION}")
    message(STATUS "CURL libraries: ${CURL_LIBRARIES}")
    message(STATUS "CURL include dirs: ${CURL_INCLUDE_DIRS}")
else()
    message(FATAL_ERROR "libcurl not found. Please install: sudo pacman -S curl")
endif()

# 查找 OpenSSL
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    message(STATUS "OpenSSL include dirs: ${OPENSSL_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "OpenSSL not found. Please install: sudo pacman -S openssl")
endif()

set(INCLUDE_DIR /usr/local/include)
set(LIB_DIR /usr/local/lib)

# 包含目录
include_directories(${INCLUDE_DIR})
include_directories(${CURL_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})

# 链接目录
link_directories(${LIB_DIR})
link_directories(${CURL_LIBRARY_DIRS})

# 添加可执行文件
add_executable(sipserver Utils/MD5.c Utils/HTTPDigest.c Utils/Log.cpp SipServer.cpp main.cpp)

# 链接库
target_link_libraries(sipserver osip2 osipparser2 eXosip2 tinyxml2 ${CURL_LIBRARIES} ${OPENSSL_LIBRARIES})

# 添加编译标志
target_compile_options(sipserver PRIVATE ${CURL_CFLAGS_OTHER})