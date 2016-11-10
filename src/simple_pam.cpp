#include <random>
#include <stdio.h>
#include <string>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

//#include "authenticator.h"

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS;
}

/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
    int retval ;
    struct pam_conv *conv ;

    retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ; 
    if( retval==PAM_SUCCESS ) {
        retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
    }

    return retval ;
}

#define LOG(fmt, ...) if(!silent) printf(fmt, ##__VA_ARGS__)

/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
    int retval;
    bool silent = flags & PAM_SILENT;

    const char* username = NULL;
    retval = pam_get_user(pamh, &username, NULL);

    if (retval != PAM_SUCCESS) {
        return retval;
    }
    
    LOG("Hello, %s", username);

    {
        /* generating a random one-time code */
        std::string request = std::to_string(std::random_device{} ());
        char prompt[100];
        snprintf(prompt, sizeof(prompt), "Type that number back: %s\n", request.c_str());
        struct pam_message msg, *pmsg[1];
        struct pam_response *resp = NULL;

        msg.msg_style = PAM_PROMPT_ECHO_ON;
        msg.msg = prompt;
        pmsg[0] = &msg;

        retval = converse(pamh, 1, pmsg, &resp);
        if (retval != PAM_SUCCESS) {
            return retval;
        }

        if (!resp || !resp[0].resp) {
            return PAM_AUTH_ERR;
        }

        LOG("Request was \"%s\", answer is \"%s\"\n", 
            request.c_str(), resp[0].resp);

        if (request != resp[0].resp) {
            return PAM_AUTH_ERR;
        }
    }

    return PAM_SUCCESS;
}
