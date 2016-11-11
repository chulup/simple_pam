set(PAM_SOURCES
    simple_pam.cpp
    random_authenticator.cpp
)
set(PAM_TESTER
    test.c
)

add_library(simple_pam SHARED ${PAM_SOURCES})
set_target_properties(simple_pam
    PROPERTIES
    PREFIX ""
    CXX_STANDARD 14
)
target_link_libraries(simple_pam 
    ${Poco_LIBRARIES}
)

add_executable(pam_test ${PAM_TESTER})
target_link_libraries(pam_test 
    ${PAM_LIBRARIES}
    ${Poco_LIBRARIES}
)
