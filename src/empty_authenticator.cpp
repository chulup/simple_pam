#include "authenticator.h"

class EmptyAuthenticator : public Authenticator {
public:
    std::string get_prompt(const std::string &username) override {
        return "";
    }
    bool check_response(const std::string& username,
                        const std::string& response) override {
        return true;
    }
};

std::unique_ptr<Authenticator> get_empty_authenticator() {
    std::unique_ptr<Authenticator> ret{new EmptyAuthenticator{}};
    return ret;
}
