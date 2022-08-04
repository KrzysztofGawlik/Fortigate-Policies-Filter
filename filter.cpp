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
    string ruleProperties[lfElem];
    fstream file, csv;
    int foundAt;
    string filename, in_file, out_file;

    // Flags
    bool policies = false;
    bool address_groups = false;
    bool ipv6_address_groups = false;
    bool vip_groups = false;
    bool ipv6_vip_groups = false;
    bool service_groups = false;
    bool schedule_groups = false;
    
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

    // Read line by line
    while(getline(file, line)){

        // Check for each property
        for(int i = 0; i < lfElem; i++){
            foundAt = -1;
            foundAt = line.find(show_firewall_policy[i]);

            // Found property
            if(foundAt != -1){
                sample = line.substr(foundAt+show_firewall_policy[i].length());
                ruleProperties[i] = sample; break;
            }
        }

        // Check for the "next" keyword
        sample = trim_copy(line);
        if(sample == "next"){

            // If found "next" save whole rule to a file
            cout << "Saving properties for rule: " << ruleProperties[0] << endl;
            for(int i = 0; i < lfElem; i++){
                csv << ruleProperties[i] << ",";
                ruleProperties[i] = "";
            }
            csv << endl;
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