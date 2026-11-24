#include <iostream>
#include <fstream>
#include <string>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: vex_cpp <script.vx> (vex file)\n";
        return 1;
    }
    std::ifstream in(argv[1]);
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("write.", 0) == 0) {
            std::cout << line.substr(6) << "\n";
        }
    }
    return 0;
}
