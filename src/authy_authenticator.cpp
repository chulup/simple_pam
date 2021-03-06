#include "authenticator.h"

#include <fstream>
#include <string>
#include <cpr/cpr.h>
#include <json.hpp>

#include "parameters.h"

using json = nlohmann::json;
using namespace std;

static const cpr::Url api_url = "http://api.authy.com/protected/json/";
static const auto api_request = api_url + "sms/";
static const auto api_verify = api_url + "verify/";

class AuthyAuthenticator : public Authenticator {
public:
    AuthyAuthenticator(int argc, const char **argv)
    {
        const auto filename = value_for_key(argc, argv, "config");

        std::fstream conf_file(filename);
        if (!conf_file.is_open()) {
            throw AuthError(Errors::config, "Unable to open config file");
        }

        try {
            _config = json::parse(conf_file);
        } catch(const std::exception &e) {
            throw AuthError(Errors::config, string("Unable to open config file: ") + e.what());
        }

        _auth_id = _config.value("authy-key", "");
        if (_auth_id.empty()) {
            throw AuthError(Errors::config, "No Auth Key specified in config file");
        }
        if (_config.find("users") == _config.end()) {
            throw AuthError(Errors::config, "No users listed in config file");
        }
    }

    std::string get_prompt(const std::string &username) override {
        const auto id = get_user_id(username);

        auto response = cpr::Get(api_request + id,
                cpr::Header{{"X-Authy-API-Key", _auth_id}});
#ifdef DEBUG
        std::cout << response.status_code << "\n"
            << response.header["context-type"] << std::endl;
#endif

        const auto json = json::parse(response.text);
#ifdef DEBUG
        std::cout << json.dump(4) << std::endl;
#endif

        if (json.value("success", false) == false) {
            throw AuthError(Errors::connection, string("Token request failed: ") + json.value("message", "No message"));
        }

        if (json.value("ignored", false)) {
            return "Enter the code from your Authy app: ";
        } else {
            return "Enter the code sent to your phone: ";
        }
    }

    bool check_response(const std::string& username,
            const std::string& response) override {
        const auto id = get_user_id(username);
        auto result = cpr::Get(api_verify + response + "/" + id, 
                cpr::Header{{"X-Authy-API-Key", _auth_id}});
#ifdef DEBUG
        std::cout << result.status_code << "\n"
            << result.header["context-type"]
            << result.text << std::endl;
#endif
        return result.status_code == 200;
    }

private:
    string _auth_id;
    nlohmann::json _config;

    std::string get_user_id(const std::string &username) {
        const auto user = _config["users"].value(username, json::object());
        const auto id = user.value("authy-id", "");
        if (id.empty()) {
            throw AuthError(Errors::user_unknown, "No entry for user");
        }
        return id;
    }

};

std::unique_ptr<Authenticator> get_authy_authenticator(int argc, const char **argv) {
    std::unique_ptr<Authenticator> ret{new AuthyAuthenticator{argc, argv}};
    return ret;
}
