#include <memory>

#ifdef DEBUG
#include <iostream>
#endif

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "authenticator.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

std::string value_for_key(int argc, const char **argv, const std::string &key) {
    int i = 0;
    for(; i < argc; ++i) {
        if (std::string(argv[i]).find(key) == 0) {
            break;
        }
    }
    if (i < argc) {
        return std::string(argv[i]).substr(key.length()+1);
    } else {
        return "";
    }
}

std::unique_ptr<Authenticator> get_authenticator(int argc, const char **argv) {
    auto type = value_for_key(argc, argv, "type");
#ifdef DEBUG
    std::cout << "auth type: " << type << std::endl;
#endif
    if (type == "random") {
        return get_random_authenticator();
    } 
    else if (type == "authy") {
        auto config = value_for_key(argc, argv, "config");
        if (!config.empty()) {
            return get_json_authenticator(config);
        }
    }
    return get_empty_authenticator();
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
    int retval;

    const char* username = NULL;
    retval = pam_get_user(pamh, &username, NULL);

    if (retval != PAM_SUCCESS) {
        return retval;
    }
#ifdef DEBUG
    std::cout << "username: " << username << std::endl;
#endif

    std::unique_ptr<Authenticator> authenticator;
    try {
        authenticator = get_authenticator(argc, argv);
    } catch (std::exception &e) {
        std::cerr << e.what();
        return PAM_AUTHINFO_UNAVAIL;
    }

    try {
        if (!authenticator->known_user(username)) {
            return PAM_USER_UNKNOWN;
        }
    } catch(std::exception &e) {
        std::cerr << e.what() << std::endl;
        return PAM_AUTH_ERR;
    }

    auto prompt = authenticator->get_prompt(username);
#ifdef DEBUG
    std::cout << "prompt: " << prompt << std::endl;
#endif
    if (!prompt.empty()) {
        char *response = NULL;
        retval = pam_prompt(pamh,
                PAM_PROMPT_ECHO_ON,
                &response,
                "%s",
                prompt.c_str());

        // Do not use response after that line!
        // TODO: check if it is legal to provide resp_p.get() to pam_prompt
        std::unique_ptr<char, decltype(::free) *> resp_p {response, ::free};

        if (retval != PAM_SUCCESS) {
            return retval;
        }

        if (!resp_p) {
            return PAM_AUTH_ERR;
        }

        try{
            if (!authenticator->check_response(username, response)) {
                return PAM_AUTH_ERR;
            }
        } catch(std::exception &e) {
            std::cerr << e.what() << std::endl;
            return PAM_AUTHINFO_UNAVAIL;
        }
    }

    return PAM_SUCCESS;
}
