# We don't need to build header-only library
set(JSON_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/json/src PARENT_SCOPE)
#set(BuildTests OFF)
#add_subdirectory(json)

set(ENV{BUILD_CPR_TESTS} OFF)
set(ENV{GENERATE_COVERAGE} OFF)
set(ENV{USE_SYSTEM_CURL} ON)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fPIC)
add_subdirectory(cpr)
