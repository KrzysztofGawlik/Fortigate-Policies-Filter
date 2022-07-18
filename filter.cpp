#include <iostream>
#include <fstream>
#include <algorithm> 
#include <cctype>
#include <locale>
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
    cout << "It converts \'show firewall policy\' output from FortiGate firewall CLI to CSV file." << endl;
    cout << "Please put the .exe & output in .txt in the same directory. Run the app, when asked" << endl;
    cout << "for filename, provide it with extension, eg. fw_output.txt ." << endl;
    cout << "CSV file will be created for you!" << endl;
    cout << string(85, '*') << endl;
    cout << "Made by Krzysztof Gawlik -- 06/2022" << endl;
    cout << "Version 1.0.0 - not official" << endl;
    cout << "!!! USE AT YOUR OWN RISK !!!" << endl;
    cout << string(85, '*') << endl;
}

int main(void){

    string line, sample;
    string lookingFor[] = {"edit ", 
                            "set srcintf ",
                            "set dstintf ",
                            "set srcaddr ",
                            "set dstaddr ",
                            "set action ",
                            "set schedule ",
                            "set service ",
                            "set logtraffic ",
                            "set nat "};
    int lfElem = sizeof(lookingFor)/sizeof(lookingFor[0]);
    string ruleProperties[lfElem];
    fstream file, csv;
    int foundAt;
    string filename;
    
    greeting();
    cout << "Provide filename with \"show firewall policy\" output: ";
    cin >> filename;
    cout << "Trying to open \""<<filename<<"\"..." << endl;
    file.open(filename, fstream::in);
    if(file.is_open()){
        cout << "File opened successfully!" << endl;    
    } else {
        cout << "Error: file cannot be opened or is not present!" << endl;
        cin.sync(); cin.get();
        exit(1);
    }
    cout << "Press any key to start analysis..." << endl;
    cin.sync(); cin.get();
    csv.open("converted.csv", fstream::out);

    // Add column names
    for(string s : lookingFor){
        csv << s << ",";
    }
    csv << endl;

    while(getline(file, line)){

        for(int i = 0; i < lfElem; i++){
            foundAt = -1;
            foundAt = line.find(lookingFor[i]);
            if(foundAt != -1){
                sample = line.substr(foundAt+lookingFor[i].length());
                ruleProperties[i] = sample; break;
            }
        }
        sample = trim_copy(line);
        if(sample == "next"){
            cout << "Saving properties for rule: " << ruleProperties[0] << endl;
            for(int i = 0; i < lfElem; i++){
                csv << ruleProperties[i] << ",";
                ruleProperties[i] = "";
            }
            csv << endl;
        }
    }

    cout << "Closing files..." << endl;
    file.close();
    csv.close();
    cout << "Converting complete!\nPress any key to quit..." << endl;
    cin.sync(); cin.get();
}