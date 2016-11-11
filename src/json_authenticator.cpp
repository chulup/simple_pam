#include "authenticator.h"
#include <string>

#include <Poco/Util/JSONConfiguration.h>

class JSONConfigAuthenticator : public Authenticator {
public:
    std::string get_prompt(const std::string &username) override {
        random = std::random_device{} ();

        return std::string("Type \"") + std::to_string(random) + "\": ";
    }
    bool check_response(const std::string& username,
                        const std::string& response) override {
        return response == std::to_string(random);
    }

private:
    unsigned int random;
};

std::unique_ptr<Authenticator> get_json_authenticator(const std::string &config) {
    std::unique_ptr<Authenticator> ret{new JSONConfigAuthenticator{}};
    return ret;
}
