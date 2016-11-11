cmake_minimum_required(VERSION 3.2)
project(simple_pam CXX C)

set(ENABLE_POCO OFF CACHE BOOL "Use POCO libraries")
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules")

find_package(PAM REQUIRED)

if (ENABLE_POCO)
    find_package(Poco REQUIRED Util XML JSON Foundation)
endif()

add_subdirectory(src)
