//  Copyright (C) Intel Corporation, 2015 All Rights Reserved.
/******************************************************************************************
FILENAME:    ISV-APP.cpp
DESCRIPTION : It is the top level class that includes the other classes of the project 
			to perform the end to end remote attesttaion with the server. 
*****************************************************************************/
#include "stdafx.h"
#include "ISV-APP.h"
using namespace std;

bool verbose = false;
bool b_pse = false;
std::string url = "";
bool keepEnclave = true; 

string findValue(string search) {
	string line;
	string URI;
	ifstream configFile;
	if (search != ""){
		configFile.open("App.config.txt");
		if (configFile.is_open()){
			int curPos = 0;
			/*each line in the file is fetched and searched to find the search string
			If the search string is found, that line number is assigned to the curPos
			the loop breaks when the first occurence of the search string is found. If it is not found,
			the loop exits after the last line of the file assuming the "search string is not used in
			the comments"
			*/
			while (getline(configFile, line)){
				curPos = (int)line.find(search);
				if (curPos >= 0)
					break;
			}
			if (curPos >= 0){
				int endpos = (int)line.find(':');
				URI = line.substr(endpos + 1);
			}
			else {
				cout << " ***Unable to find the search String, " << search << endl;
				AbortProcess();
			}
			configFile.close();
		}
		else{
			cout << " ****Unable to open the Configuration File ***" << endl;
			AbortProcess();
		}
	}
	return URI;
}

void InitSettings(){
	verbose = (strcmp(findValue("verboseFlag").c_str(), "true") == 0);
	b_pse = (strcmp("true", findValue("b_pseFlag").c_str()) == 0);
	keepEnclave = (strcmp("true", findValue("keepEnclave").c_str()) == 0);
	url = findValue("SPUri");
}

void main(){
	InitSettings();
	cout << "Intel Remote Attestation End-to-End Sample Client" << endl;
	cout << "Remote attestation will be done if necessary to obtain key for encrypt/decrypt operation" << endl;
	std::string buf;

	if (keepEnclave){
		// No need to suppress remote attestation
		CreateEnclave();
	}
	while (1){
		cout << endl << "Type message to encrypt/decrypt, / to delete sealed file, or * to exit" << endl;
		getline(cin, buf);
		if (buf.compare("*") == 0)
			break;

		if (buf.compare("/") == 0){
			RemoveFile();
			cout << "   Sealed file deleted" << endl;
		}
		else{
			if (EncryptDecrypt(buf))
				cout << "   EncryptDecrypt was successful" << endl;
			else
				cout << "   EncryptDecrypt was NOT successful" << endl;
		}
	}
	AbortProcess();
}
