/**
 * @file TestLicenseTimeStampOperationMain.cpp
 * @author Hailun Tan (hailun.tan@gmail.com)
 * @brief 
 * 
 * It is for the software developer role application in JTech. All Rights Reserved to the author 
 * 
 * This is the main function to test the timestamp operation library
 * 
 * @version 0.1
 * @date 2022-02-16
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <iostream>
#include "../include/LicenseTimeStamp.h"
#include "math.h"
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#endif

using namespace std;

const string EncryptTimeStampFile = "Encrypted.txt";
const string TimeStampCheckSumFile = "checksum.txt";
const double LicenseDuration = 0.1;
/**
 * @brief 
 * The main function to test the timestamp operation library
 * @return int 
 * return 0 to exit the program
 * 
 */
int main()
{
    // create a new license timestamp operation instance 
    LicenseTimeStampOperation test = LicenseTimeStampOperation(EncryptTimeStampFile, TimeStampCheckSumFile, LicenseDuration);

    string output = "test";
    // The container to hold the encrypted timestamp
    double encryptedOut[SIZE];
    // the variable to store the operational state in each API, required by the code test.
    OperationState result;

    // create the encrypted timestamp file if it does not exist. code test requirement 1
    if ((result = test.CreateTimeStampFile(encryptedOut,output)) != SUCCESS) {
        cout << "Fail to create TimeStamp file. error: " << test.OperationStateToString(result) <<endl;    
    } 

    // call the API to inspect the timestamp and store it into a string (i.e., @output as the parameter of this function), required by the code test (requirement 3)
    
    if ((result = test.InspectTimeStamp(output)) != SUCCESS) {
        cout << " failed to inspect the timestamp. Error: " << test.OperationStateToString(result) << endl;
        return -1;
    } else {
        cout << "Decrypted timestamp is: " << output  << endl;

        // call the API to check its expiry and return the operational code accordingly (i.e., code test requirement 2)
        string expired = test.IsTimeStampExpired()!= true ? "not" : "" ;
        cout << "License has " << expired << " expired." << endl;
    }

    return 0;
}