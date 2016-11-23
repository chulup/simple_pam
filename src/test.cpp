#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

#include <iostream>
#include <fstream>
#include <cpr/cpr.h>
#include <json.hpp>

const struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[]) {
    /*
    auto config = "/home/chulup/simple-pam.json";
    std::fstream conf_file(config);
    auto         _config = nlohmann::json::parse(conf_file);

    auto   _auth_id = _config.value("auth-key", "");
    if (_auth_id.empty()) {
        throw std::logic_error("No Auth Key specified in config file");
    }
    if (_config.find("users") == _config.end()) {
        throw std::logic_error("No users listed in config file");
    }
    std::cout << _config.dump(4) << std::endl;
    std::fstream conf_file("/home/chulup/simple-pam.json");
    auto config = nlohmann::json(conf_file);
    std::cout << config.dump(4) << std::endl;

    const cpr::Url api_url = "http://api.authy.com/protected/json/";
    const auto api_request = api_url + "sms/";
    const auto api_verify = api_url + "verify/";
    const auto auth_id = cpr::Header{{"X-Authy-API-Key", "iwN27DChsE1rHl6WEZRKt6v2DrFDDorv"}};
    const auto user_id = "28567126";

    auto response = cpr::Get(api_request + user_id, auth_id);
    std::cout << response.status_code << "\n"
        << response.header["context-type"] << std::endl;

    auto json = nlohmann::json::parse(response.text);
    std::cout << json.dump(4) << std::endl;

    if (!json.value("success", false)) {
        std::cout << "Token request failed";
        if (json.find("message") != json.end()) {
            std::cout << " with message: " << json["message"] << std::endl;
        }        
    }

    if (json.value("ignored", false)) {
        std::cout << "You have Authy app installed. Please enter the code it shows." << std::endl;
    } else {
        std::cout << "Token was sent to your phone" << std::endl;
    }

    std::cout << "Enter your code, please: ";
    std::string code;
    std::cin >> code;

    auto response2 = cpr::Get(api_verify + code + "/" + user_id, auth_id);
    std::cout << response2.status_code << "\n"
        << response2.header["context-type"]
        << response2.text << std::endl;
        */

    pam_handle_t* pamh = NULL;
    int retval;
    const char* user = "nobody";

    if(argc != 2) {
        printf("Usage: app [username]\n");
        exit(1);
    }

    user = argv[1];

    retval = pam_start("check_user", user, &conv, &pamh);

    // Are the credentials correct?
    if (retval == PAM_SUCCESS) {
        printf("Credentials accepted.\n");
        retval = pam_authenticate(pamh, 0);
    }

    // Can the accound be used at this time?
    if (retval == PAM_SUCCESS) {
        printf("Account is valid.\n");
        retval = pam_acct_mgmt(pamh, 0);
    }

    // Did everything work?
    if (retval == PAM_SUCCESS) {
        printf("Authenticated\n");
    } else {
        printf("Not Authenticated\n");
    }

    // close PAM (end session)
    if (pam_end(pamh, retval) != PAM_SUCCESS) {
        pamh = NULL;
        printf("check_user: failed to release authenticator\n");
        exit(1);
    }

    return retval == PAM_SUCCESS ? 0 : 1;
}
