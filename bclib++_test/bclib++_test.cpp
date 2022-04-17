#include <iostream>
#include "bclib++.hpp"

int main()
{
    try{

        BCLib* lib = new BCLib("ROCKET_LEAGUE", "Plugin Test", [&](std::string msg) {
            std::cout << msg << std::endl;
        });
        lib->StartCBServer();
        std::cout << "Server stopped." << std::endl;
    } catch(std::exception ex) {
        std::cout << ex.what() << std::endl;
    }
    return 0;
}