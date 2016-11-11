#ifdef ENABLE_POCO

#include "authenticator.h"
#include <string>

#include <Poco/Util/JSONConfiguration.h>

class JSONConfigAuthenticator : public Authenticator {
public:
    JSONConfigAuthenticator(const std::string &config) :
        _config(config) {
    }


    std::string get_prompt(const std::string &username) override {
        return "";
    }
    bool check_response(const std::string& username,
                        const std::string& response) override {
        return true;
    }

private:
    Poco::Util::JSONConfiguration _config;
};

std::unique_ptr<Authenticator> get_json_authenticator(const std::string &config) {
    std::unique_ptr<Authenticator> ret{new JSONConfigAuthenticator{config}};
    return ret;
}

#endif // ENABLE_POCO
