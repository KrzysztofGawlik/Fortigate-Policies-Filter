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
    cout << "It converts \'show firewall [...]\' output from FortiGate firewall CLI to CSV files." << endl;
    cout << "Please put the .exe & output in .txt in the same directory. Run the app, when asked" << endl;
    cout << "for filename, provide it without extension, eg. fw_output ." << endl;
    cout << "CSV files will be created for you!" << endl;
    cout << string(85, '*') << endl;
    cout << "Made by Krzysztof Gawlik -- 08/2022" << endl;
    cout << "Version 2.0.0 - not official" << endl;
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

bool checkForExactMatch(string line, string confType){
    if(line == confType){
        return true;
    }
    return false;
}

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
    string show_firewall_rest[] = {"edit ",      // Name
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
    //filename = "sources_restricted/total_ext";
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

    currentLookup CL = OUTSIDE;

    bool configurationMode = false;
    bool editMode = false;
    int lineAcceptedForIndex = -1;
    bool csvOpened = false;

    // Read line by line
    while(!file.eof()){
        getline(file, line);
        trim(line);

        if(!configurationMode){
            if(checkForExactMatch(line, "config firewall policy")) CL = POLICIES;
            else if(checkForExactMatch(line, "config firewall addrgrp6")) CL = IPV6_ADDR_GROUPS;
            else if(checkForExactMatch(line, "config firewall addrgrp")) CL = ADDR_GROUPS;
            else if(checkForExactMatch(line, "config firewall vipgrp6")) CL = IPV6_VIP_GROUPS;
            else if(checkForExactMatch(line, "config firewall vipgrp")) CL = VIP_GROUPS;
            else if(checkForExactMatch(line, "config firewall service group")) CL = SERVICE_GROUPS;
            else if(checkForExactMatch(line, "config firewall schedule group")) CL = SCHEDULE_GROUPS;

            if(CL != OUTSIDE){
                configurationMode = true; continue;
            }
        }

        if(configurationMode){
            if(checkForExactMatch(line, "end")){
                csv.close();
                csvOpened = false;
                CL = OUTSIDE; configurationMode = false; continue;
            }

            if(checkForExactMatch(line.substr(0,4), "edit")){
                editMode = true;
            }
            if(editMode){
                if(checkForExactMatch(line, "next")){

                    cout << "Saving properties for object: " << ruleProperties[0] << endl;
                    for(int i = 0; i < lfElem; i++){
                        csv << ruleProperties[i] << ",";
                        ruleProperties[i] = "";
                    }
                    csv << endl;

                    editMode = false; continue;
                }

                // Place for processing properties
                switch(CL){

                    case POLICIES: {
                        if(!csvOpened){
                            out_file = "CSV_POLICIES.csv";
                            csv.open(out_file, fstream::out);
                            if(csv.is_open()) {
                                csvOpened = true;
                            }
                            else {
                                cout << "Error while opening CSV for writing - aborting...";
                                cin.sync(); cin.get();
                                exit(1);
                            }
                            // Add column names
                            for(string s : show_firewall_policy){
                                csv << s << ",";
                            }
                            csv << endl;
                        }
                        for(int i = 0; i < lfElem; i++){
                            if(line.find(show_firewall_policy[i]) == 0){
                                ruleProperties[i] = line.substr(show_firewall_policy[i].length());
                                // line correct
                                lineAcceptedForIndex = i;
                                break;
                            }
                            if(lineAcceptedForIndex != -1 && line.find("set ") != 0){
                                ruleProperties[lineAcceptedForIndex].append(line);
                                break;
                            } else {
                                lineAcceptedForIndex = -1;
                            }
                        }
                        continue;
                    }

                    case VIP_GROUPS:
                    case IPV6_VIP_GROUPS:
                    case ADDR_GROUPS:
                    case IPV6_ADDR_GROUPS:
                    case SERVICE_GROUPS:
                    case SCHEDULE_GROUPS: {
                        if(!csvOpened){
                            if(CL == VIP_GROUPS) out_file = "CSV_VIP_GROUPS.csv";
                            if(CL == IPV6_VIP_GROUPS) out_file = "CSV_IPV6_VIP_GROUPS.csv";
                            if(CL == ADDR_GROUPS) out_file = "CSV_ADDR_GROUPS.csv";
                            if(CL == IPV6_ADDR_GROUPS) out_file = "CSV_IPV6_ADDR_GROUPS.csv";
                            if(CL == SERVICE_GROUPS) out_file = "CSV_SERVICE_GROUPS.csv";
                            if(CL == SCHEDULE_GROUPS) out_file = "CSV_SCHEDULE_GROUPS.csv";
                            csv.open(out_file, fstream::out);
                            if(csv.is_open()) {
                                csvOpened = true;
                            } else {
                                cout << "Error while opening CSV for writing - aborting...";
                                cin.sync(); cin.get();
                                exit(1);
                            }
                            // Add column names
                            for(string s : show_firewall_rest){
                                csv << s << ",";
                            }
                            csv << endl;
                        }
                        for(int i = 0; i < lfElemRest; i++){
                            if(line.find(show_firewall_rest[i]) == 0){
                                ruleProperties[i] = line.substr(show_firewall_rest[i].length());
                                // line correct
                                lineAcceptedForIndex = i;
                                break;
                            }
                            if(lineAcceptedForIndex != -1 && line.find("set ") != 0){
                                ruleProperties[lineAcceptedForIndex].append(line);
                                break;
                            } else {
                                lineAcceptedForIndex = -1;
                            }
                        }
                        continue;
                    }
                }

            }
        }

    }

    // End of analysis - stop clock, print duration, close files
    auto stop = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(stop-start);
    cout << "Closing files..." << endl;
    file.close();
    if(csv.is_open()) csv.close();
    printf("Converting complete (%d ms)!\n Press any key to quit...", duration);
    cin.sync(); cin.get();
}