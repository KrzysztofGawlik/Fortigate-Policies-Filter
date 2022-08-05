#include <iostream>
#include <fstream>
#include <algorithm> 
#include <cctype>
#include <locale>
#include <chrono>
#include <string>
using namespace std;

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

// trim from start (copying)
static inline std::string ltrim_copy(std::string s) {
    ltrim(s);
    return s;
}

// trim from end (copying)
static inline std::string rtrim_copy(std::string s) {
    rtrim(s);
    return s;
}

// trim from both ends (copying)
static inline std::string trim_copy(std::string s) {
    trim(s);
    return s;
}

void greeting(void){
    cout << string(85, '*') << endl;
    cout << "Hello! Thank you for using this little program :)" << endl;
    cout << "It converts \'show firewall [...]\' output from FortiGate firewall CLI to CSV file." << endl;
    cout << "Please put the .exe & output in .txt in the same directory. Run the app, when asked" << endl;
    cout << "for filename, provide it without extension, eg. fw_output ." << endl;
    cout << "CSV file will be created for you!" << endl;
    cout << string(85, '*') << endl;
    cout << "Made by Krzysztof Gawlik -- 08/2022" << endl;
    cout << "Version 2.0.0 (beta) - not official" << endl;
    cout << "!!! USE AT YOUR OWN RISK !!!" << endl;
    cout << string(85, '*') << endl;
}

// Flags
enum currentLookup { 
    POLICIES,               // config firewall policy
    ADDR_GROUPS,            // config firewall addrgrp
    IPV6_ADDR_GROUPS,       // config firewall addrgrp6
    VIP_GROUPS,             // config firewall vipgrp
    IPV6_VIP_GROUPS,        // config firewall vipgrp6
    SERVICE_GROUPS,         // config firewall service group
    SCHEDULE_GROUPS,        // config firewall schedule group
    OUTSIDE                 // when none of the above
};

int main(void){

    // It applies only to command: show firewall policy
    string show_firewall_policy[] = {"edit ",   // ID
                            "set name ",        // Name
                            "set action ",      // Action
                            "set srcintf ",     // From
                            "set srcaddr ",     // Source
                            "set dstintf ",     // To
                            "set dstaddr ",     // Destination
                            "set schedule ",    // Schedule    
                            "set service ",     // Service
                            "set logtraffic ",  // Log
                            "set nat "};        // NAT

    // It applies to commands: show firewall addrgrp / addrgrp6/ vipgrp / vipgrp6 / service group / schedule group
    string show_firewall_rest[] = {"edit",      // Name
                            "set member "};     // Details

    string line, sample;
    const int lfElem = sizeof(show_firewall_policy)/sizeof(show_firewall_policy[0]);
    const int lfElemRest = sizeof(show_firewall_rest)/sizeof(show_firewall_rest[0]);
    string ruleProperties[lfElem];
    fstream file, csv;
    int foundAt;
    string filename, in_file, out_file;
    
    // Welcome screen and open file, create output file, confirm and start clock
    greeting();
    cout << "Provide filename with \"show firewall policy\" output: ";
    cin >> filename;
    cout << "Trying to open \""<<filename<<".txt\"..." << endl;
    in_file = filename + ".txt";
    file.open(in_file, fstream::in);
    if(file.is_open()){
        cout << "File opened successfully!" << endl;    
    } else {
        cout << "Error: file cannot be opened or is not present!" << endl;
        cin.sync(); cin.get();
        exit(1);
    }
    cout << "Press any key to start analysis..." << endl;
    cin.sync(); cin.get();
    auto start = chrono::high_resolution_clock::now();
    out_file = filename + ".csv";
    csv.open(out_file, fstream::out);

    // Add column names
    for(string s : show_firewall_policy){
        csv << s << ",";
    }
    csv << endl;

    currentLookup CL = OUTSIDE;

    // Read line by line
    while(getline(file, line)){
        trim(line);

        // Check what is current mode or skip if none
        if (CL == OUTSIDE){
            if(line.find("config firewall policy") == 0){
                CL = POLICIES;
                continue;
            }
            if(line.find("config firewall addrgrp6") == 0){
                CL = IPV6_ADDR_GROUPS;
                continue;
            }
            if(line.find("config firewall addrgrp") == 0){
                CL = ADDR_GROUPS;
                continue;
            }
            if(line.find("config firewall vipgrp6") == 0){
                CL = IPV6_VIP_GROUPS;
                continue;
            }
            if(line.find("config firewall vipgrp") == 0){
                CL = VIP_GROUPS;
                continue;
            }
            if(line.find("config firewall service group") == 0){
                CL = SERVICE_GROUPS;
                continue;
            }
            if(line.find("config firewall schedule group") == 0){
                CL = SCHEDULE_GROUPS;
                continue;
            }
            continue;
        }

        int propertyIndicator;
        if(CL == POLICIES){
            // Check for each property for policy
            for(int i = 0; i < lfElem; i++){
                foundAt = -1;
                foundAt = line.find(show_firewall_policy[i]);

                // Found property
                if(foundAt == 0){
                    propertyIndicator = i;
                    sample = line.substr(foundAt+show_firewall_policy[i].length());
                    ruleProperties[i] = sample; break;
                } else if (line == "next") {
                    // If found "next" save whole rule to a file
                    cout << "Saving properties for rule: " << ruleProperties[0] << endl;
                    for(int i = 0; i < lfElem; i++){
                        csv << ruleProperties[i] << ",";
                        ruleProperties[i] = "";
                    }
                    csv << endl;
                    break;
                } else if (line == "end") {
                    // If found "end" exit policies mode
                    CL = OUTSIDE;
                    break;
                } else if (line.substr(0,3) != "set") {
                    ruleProperties[propertyIndicator] += line;
                }
            }
        }
    }

    // End of analysis - stop clock, print duration, close files
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop-start);
    cout << "Closing files..." << endl;
    file.close();
    csv.close();
    printf("Converting complete (%d ms)!\n Press any key to quit...", duration);
    cin.sync(); cin.get();
}