#include <string>
class Rule{
    public:
        int ID;
        std::string name;
        std::string action;
        std::string sourceInterface;
        std::string sourceAddress;
        std::string destinationInterface;
        std::string destinationAddress;
        std::string schedule;
        std::string service;
        std::string logTraffic;
        std::string nat;
};