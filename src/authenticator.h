#pragma once
#include <memory>
#include <string>

class Authenticator {
public:
    ~Authenticator() = default;

    virtual std::string get_prompt(const std::string &username) = 0;
    virtual bool check_response(const std::string& username,
                                const std::string& response) = 0;
};

std::unique_ptr<Authenticator> get_random_authenticator();
