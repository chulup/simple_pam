#include <memory>

#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>

#include "authenticator.h"

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
        auto authenticator = get_random_authenticator();
        char *response = NULL;

        retval = pam_prompt(pamh,
            PAM_PROMPT_ECHO_ON,
            &response,
            "%s",
            authenticator->get_prompt(username).c_str());

        // Do not use response after that line!
        // TODO: check if it is legal to provide resp_p.get() to pam_prompt
        std::unique_ptr<char, decltype(free) *> resp_p {response, free};

        if (retval != PAM_SUCCESS) {
            return retval;
        }

        if (!resp_p) {
            return PAM_AUTH_ERR;
        }

        if (!authenticator->check_response(username, response)) {
            return PAM_AUTH_ERR;
        }
    }

    return PAM_SUCCESS;
}
