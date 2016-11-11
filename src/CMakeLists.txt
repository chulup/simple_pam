set(PAM_SOURCES
    simple_pam.cpp
    empty_authenticator.cpp
    json_authenticator.cpp
    random_authenticator.cpp
)
set(PAM_TESTER
    test.c
)

set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")

add_library(simple_pam SHARED ${PAM_SOURCES})
set_target_properties(simple_pam
    PROPERTIES
    PREFIX ""
    CXX_STANDARD 14
)
target_include_directories(simple_pam
    SYSTEM
    PRIVATE ${Poco_INCLUDE_DIRS}
)
target_link_libraries(simple_pam 
    ${PAM_LIBRARIES}
    ${Poco_LIBRARIES}
)

add_executable(pam_test ${PAM_TESTER})
target_link_libraries(pam_test 
    ${PAM_LIBRARIES}
    ${Poco_LIBRARIES}
)
