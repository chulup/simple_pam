cmake_minimum_required(VERSION 3.2)
project(simple_pam CXX C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules")

find_package(PAM REQUIRED)

add_subdirectory(src)
