#include <iostream>
#include <random>
#include <string>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

//#include "authenticator.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
    int retval;
    bool silent = flags & PAM_SILENT;

    const char* username = NULL;
    retval = pam_get_user(pamh, &username, NULL);

    if (retval != PAM_SUCCESS) {
        return retval;
    }
    
    {
        std::string request = std::to_string(std::random_device{} ());
        char *response = NULL;

        retval = pam_prompt(pamh,
            PAM_PROMPT_ECHO_ON,
            &response,
            "Type \"%s\": ",
            request.c_str());;
        if (retval != PAM_SUCCESS) {
            return retval;
        }

        if (!response) {
            return PAM_AUTH_ERR;
        }

        if (request != response) {
            return PAM_AUTH_ERR;
        }
    }

    return PAM_SUCCESS;
}
