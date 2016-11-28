#include "authenticator.h"

#include <fstream>
#include <string>
#include <cpr/cpr.h>
#include <json.hpp>

using json = nlohmann::json;
using namespace std;

static const cpr::Url api_url = "http://api.authy.com/protected/json/";
static const auto api_request = api_url + "sms/";
static const auto api_verify = api_url + "verify/";

class AuthyAuthenticator : public Authenticator {
public:
    AuthyAuthenticator(const std::string &config) :
        _config_file(config) 
    {
        std::fstream conf_file(config);
        if (!conf_file.is_open()) {
            throw AuthError(Errors::config, "Unable to open config file");
        }

        _config = json::parse(conf_file);

        _auth_id = _config.value("auth-key", "");
        if (_auth_id.empty()) {
            throw AuthError(Errors::config, "No Auth Key specified in config file");
        }
        if (_config.find("users") == _config.end()) {
            throw AuthError(Errors::config, "No users listed in config file");
        }
    }

    std::string get_prompt(const std::string &username) override {
        const auto user = _config["users"].value(username, json::object());
        const auto id = user.value("id", "");
        if (id.empty()) {
            throw AuthError(Errors::user_unknown, "No entry for user");
        }

        auto response = cpr::Get(api_request + id,
                cpr::Header{{"X-Authy-API-Key", _auth_id}});
#ifdef DEBUG
        std::cout << response.status_code << "\n"
            << response.header["context-type"] << std::endl;
#endif

        auto json = json::parse(response.text);
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
        const auto user = _config["users"].value(username, json::object());
        const auto id = user.value("id", "");
        if (id.empty()) {
            throw AuthError(Errors::user_unknown, "No entry for user");
        }

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
    string _config_file;
    string _auth_id;
    nlohmann::json _config;
};

std::unique_ptr<Authenticator> get_authy_authenticator(const std::string &config) {
    std::unique_ptr<Authenticator> ret{new AuthyAuthenticator{config}};
    return ret;
}
