#include "authenticator.h"
#include <random>
#include <string>

class RandomAuthenticator : public Authenticator {
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

std::unique_ptr<Authenticator> get_random_authenticator() {
    std::unique_ptr<Authenticator> ret{new RandomAuthenticator{}};
    return ret;
}
