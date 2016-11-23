set(PAM_SOURCES
    simple_pam.cpp
    empty_authenticator.cpp
    json_authenticator.cpp
    random_authenticator.cpp
)
set(PAM_TESTER
    test.cpp
)

set (CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")

add_library(simple_pam SHARED ${PAM_SOURCES})
set_target_properties(simple_pam
    PROPERTIES
    PREFIX ""
)
target_link_libraries(simple_pam
    ${PAM_LIBRARIES}
    ${CPR_LIBRARIES}
)
target_include_directories(simple_pam
    PRIVATE
    ${CPR_INCLUDE_DIRS}
    ${JSON_INCLUDE_DIRS}
)

install(TARGETS simple_pam 
    LIBRARY DESTINATION lib)


set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -fPIC)

add_executable(pam_test ${PAM_TESTER})
target_link_libraries(pam_test 
    ${PAM_LIBRARIES}
    ${CPR_LIBRARIES}
)
target_include_directories(pam_test
    PRIVATE
    ${CPR_INCLUDE_DIRS}
    ${JSON_INCLUDE_DIRS}
)
