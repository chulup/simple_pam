#pragma once
#include <memory>
#include <string>
#include <stdexcept>

class Authenticator {
public:
    ~Authenticator() = default;

    virtual std::string get_prompt(const std::string &username) = 0;
    virtual bool check_response(const std::string& username,
                                const std::string& response) = 0;
};

std::unique_ptr<Authenticator> get_authenticator(int argc, const char **argv);
std::unique_ptr<Authenticator> get_empty_authenticator();
std::unique_ptr<Authenticator> get_random_authenticator();
std::unique_ptr<Authenticator> get_authy_authenticator(int argc, const char **argv);

std::string value_for_key(int argc, const char **argv, const std::string &key);

enum class Errors {
    general,
    user_unknown,
    connection,
    config
};
class AuthError : public std::logic_error {
public:
    AuthError(Errors err, const std::string &message = "") :
        std::logic_error(message),
        error(err)
    { }

    const Errors error;
};
