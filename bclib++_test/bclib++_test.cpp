#include <iostream>
#include "bclib++.h"

int main()
{
    BCLib *lib = new BCLib("ROCKET_LEAGUE", "Plugin Test", [&](std::string msg) {
        std::cout << msg << std::endl;
    });
    lib->StartCBServer();
    return 0;
}