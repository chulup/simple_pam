#include "authenticator.h"

#include <iostream>

std::unique_ptr<Authenticator> get_authenticator(int argc, const char **argv) {
    auto type = value_for_key(argc, argv, "type");
#ifdef DEBUG
    std::cout << "auth type: " << type << std::endl;
#endif
    if (type == "random") {
        return get_random_authenticator();
    } 
    else if (type == "authy") {
        return get_authy_authenticator(argc, argv);
    }
    return get_empty_authenticator();
}

std::string value_for_key(int argc, const char **argv, const std::string &key) {
    int i = 0;
    for(; i < argc; ++i) {
        if (std::string(argv[i]).find(key) == 0) {
            break;
        }
    }
    if (i < argc) {
        return std::string(argv[i]).substr(key.length()+1);
    } else {
        return "";
    }
}

