/**
 * @file LicenseTimeStamp.cpp
 * @author Hailun Tan (Haiun.Tan@gmail.com)
 * @brief 
 * 
 * It is for the software developer role application in JTech. All Rights Reserved to the author 
 * 
 * I used the RSA encryption/decryption to secure the license timestamp storage in file. 
 * 
 * The reason to use RSA encryption/decryption is that it was an asymmetric cryptographic opertation, which need two different set of keys to encrypt and decrypt the data. 
 * 
 * Capturing both keys posed a much more challenging and diffult job for the license crackers than capturing a single key for symmetric cryptographic operations.
 * 
 * The tamper check was placed into a seperate file. 
 * 
 * The purpose  of two seperate files is to ensure that if the encrypted license timestamp file was tampered with, the checksum for file integrity check would still remain intact to identify the encryption file tampering
 * 
 * 
 * @version 0.1
 * @date 2022-02-15
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include "../include/LicenseTimeStamp.h"
#include <iostream>
#include<stdlib.h>
#include<math.h>
#include<string.h>
#include <fstream>
#include <unordered_map>
#include <iomanip>
#include <limits>
#include <sys/stat.h>
#include <ctime>
#include <chrono>
#include <ctime> 

using namespace std;
using namespace std::chrono;


/**
 * @brief  
 * A function to return the literal description of the operational state 
 * 
 * @param v 
 * The operational state in enumeration.
 * @return const char*  
 * The literal string to describe the operational state 
 */
const char* LicenseTimeStampOperation::OperationStateToString(OperationState v)
{
  switch (v)
  {
    case SUCCESS:   return "Successful Operation";
    case INVALID_PARAMETER: return "Invalid Parameter passed to function";
    case FILE_FAIL_OPEN:   return "Failed to open a file";
    case FILE_NOT_EXIST: return "File does not exist";
    case FILE_EXIST: return "File exists";
    case TIMESTAMP_RETRIEVAL_ERROR: return "Timestamp fails to be retrieved";
    case TIMESTAMP_TAMPERED: return "Timestamp file has been tampered with";
    default:      return "Unknown State";
  }
}
/**
 * @brief Construct a new License Time Stamp Operation:: License Time Stamp Operation object
 * 
 * @param encryptionFileName 
 * The location and file name of the encrypted timestamp file
 * @param checksumFileName 
 * The location and file name of the timestamp checksum file (for file tamper check)
 * @param LicenseDuration 
 * The license duration (in days)
 */

LicenseTimeStampOperation::LicenseTimeStampOperation(string encryptionFileName, string checksumFileName, double LicenseDuration) {
  EncryptionFileName = encryptionFileName;
  CheckSumFileName = checksumFileName;
  LicenseDurationInDays = LicenseDuration;
  PrimeList.push_back(tuple<double, double>(11.0,13.0));
  PrimeList.push_back(tuple<double, double>(11.0,17.0));
  PrimeList.push_back(tuple<double, double>(11.0,19.0));
  PrimeList.push_back(tuple<double, double>(11.0,23.0));
  PrimeList.push_back(tuple<double, double>(11.0,29.0));
  PrimeList.push_back(tuple<double, double>(11.0,31.0));

  PrimeList.push_back(tuple<double, double>(11.0,37.0));
  PrimeList.push_back(tuple<double, double>(11.0,41.0));
  PrimeList.push_back(tuple<double, double>(11.0,43.0));
  PrimeList.push_back(tuple<double, double>(11.0,47.0));
  PrimeList.push_back(tuple<double, double>(11.0,53.0));
  PrimeList.push_back(tuple<double, double>(11.0,59.0));

  PrimeList.push_back(tuple<double, double>(11.0,61.0));
  PrimeList.push_back(tuple<double, double>(11.0,67.0));
  PrimeList.push_back(tuple<double, double>(11.0,71.0));
  PrimeList.push_back(tuple<double, double>(11.0,73.0));
  PrimeList.push_back(tuple<double, double>(11.0,79.0));
  PrimeList.push_back(tuple<double, double>(11.0,83.0));

  PrimeList.push_back(tuple<double, double>(11.0,89.0));
  PrimeList.push_back(tuple<double, double>(11.0,97.0));

}


/**
 * @brief 
 *  The first prime number in RSA encryption algorithm.
 *  TODO: In order to improve the entropy of the encryption algorithm, the first prime number can be randomized for each timestamp encryption operation.
 */
const double FirstPrime = 11.0;
/**
 * @brief 
 *  The second prime number in RSA encryption algorithm.
 *  TODO: In order to improve the entropy of the encryption algorithm, the second prime number can be randomized for each timestamp encryption operation.
 */
const double SecondPrime =  13.0;

/**
 * @brief 
 * A product of both prime numbers.
 */
//const double N = FirstPrime * SecondPrime;
/**
 * @brief 
 *  Computation of the Carmichael's totient function of the product 
 */

//const double PHI = (FirstPrime -1) * (SecondPrime -1);

/**
 * @brief 
 * 
 *  A function to find the Greatest Common Divisor (GCD) between two integers for RSA algorithm
 * 
 * @param a 
 * One of the integer to check GCD 
 * @param b 
 * The other integer to check GCD
 * @return int 
 * The GCD between @a and @b
 */
int gcd(int a, int b)
{
  int t;
  while (1)
  {
    t = a % b;
    if (t == 0) {
      return b;
    }
    a = b;
    b = t;
  }
}
/**
 * @brief 
 * 
 * A function to retrieve the public key from RSA algorithm
 * 
 * @return double 
 * The public key (i.e., the encryption key)
 */

double LicenseTimeStampOperation::GetPublicKey(int index) {
    
  //public key
  //e stands for encrypt
  double e = 2;

  double track;

  int  i = index % PrimeList.size();

  double PHI = ((get<0>(PrimeList[i])) - 1) * ((get<1>(PrimeList[i])) - 1);
    
  //for checking that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
  while (e < PHI)
  {
    track = gcd(e, PHI);
    if (track == 1) {
      break;
    } else {
      e++;
    }
  }

  return e;
}

/**
 * @brief 
 * 
 * A function to retrieve the private key from RSA algorithm
 * 
 * @return double 
 * The private key
 */

double LicenseTimeStampOperation::GetPrivateKey(int index, double &N) {

  //public key
  //e stands for encrypt
  double e = 2;

  double track;

  int  i = index % PrimeList.size();

  N = (get<0>(PrimeList[i])) * (get<1>(PrimeList[i]));

  double PHI = ((get<0>(PrimeList[index])) - 1) * ((get<1>(PrimeList[index])) - 1);
    
  //for checking that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
  while (e < PHI) {
    track = gcd(e, PHI);
    if (track == 1) {
      break;
    } else {
      e++;
    }
  }

  double d1 = 1 / e;
  double d = fmod(d1, PHI);

  return d;
}

/**
 * @brief 
 * 
 * A functon to convert an array of chracters into a string object
 * 
 * @param a 
 * The target character array
 * @param size 
 *  The size of the array to be converted
 * @return string 
 * The converted string
 */

string convertToString(long int *a, int size) {
  int i;
    string s = "";
    for (i = 0; i < size; i++) {
      s = s + to_string(a[i]);
    }
    return s;
}

/**
 * @brief 
 * 
 *  A function to turn an array of integers to a string, whose element's ASCII code is from the element of the integer array
 * 
 * @param a 
 *  The target interger array
 * @param size 
 *  The size of the integer array to be converted
 * @return string 
 * The converted string
 */

string convertASCIIToString(long int *a, int size) {
  int i;
    string s = "";
    for (i = 0; i < size; i++) {
        s = s + char(a[i]);
    }
    return s;
}
/**
 * @brief 
 *  A function to check if a given file with the @name exists in the current file systeem.
 * 
 * @param name 
 * 
 * The target file name (with full path) to be checked.
 * 
 * @return true
 * It means that the file exists
 * @return false 
 * It means that the file does not exist.
 */

inline bool IsFileExists (const string& name) {
  struct stat buffer;   
  return (stat (name.c_str(), &buffer) == 0); 
}

/**
 * @brief 
 * A method to create  the timestamp file when the software license started.
 * 
 * An API to address the code test requirement 1.
 * 
 * 
 * @param EncryptedOut 
 * The encrypted array in double type of values to be placed into the timestamp file
 * @param EncryptedCheckSum 
 * The checksum on the timestamp file
 * @return OperationState 
 * The operational state od this API
 */

OperationState LicenseTimeStampOperation::CreateTimeStampFile(double* EncryptedOut,string &EncryptedCheckSum)
{
  OperationState ret = SUCCESS;

  char temp;
  int i;

  string inStr;

  if (EncryptedOut == nullptr) {
    return INVALID_PARAMETER;
  }
  
  // if  the timestamp file or the checksum file exists, skip the rest of the API and return an error ("File exists") - address the code test requirement 1.3
  if (IsFileExists (EncryptionFileName) || IsFileExists(CheckSumFileName)) {
    return FILE_EXIST;
  }

  if ((ret = ConvertcurrentDateToString(inStr)) != SUCCESS) {
    EncryptedOut = nullptr;
    EncryptedCheckSum = "0";
    return ret;
  }
  if (DEBUG) {
    cout << "message to encrypt: " << inStr <<endl;
  }

  int lengthOfString = inStr.length();

  long int hashCode = 0;

  double en[SIZE];
 
  // declaring character array
  char inputCharArray[lengthOfString + 1];
 
  // copying the contents of the string to char array (conversion)
  strcpy(inputCharArray, inStr.c_str());

  if (DEBUG) {
    cout << "Input string is: " <<endl;

    for (i=0;i <lengthOfString;i++) {
      cout << "inputArray[" << i << "] = " << inputCharArray[i] <<endl;
    }
  }

  

  long int en_display[SIZE];

  
  for (i=0;i < lengthOfString; i++) {

    double publicKey = GetPublicKey(i);
    // encrypt the timestamp string using the RSA public key before it was written into a file - address the code test requirement 1.1
    en[i] = pow(inputCharArray[i],publicKey);
    // save the encrypted timestamp as the output fo this function so that it can be used later - address the code test requirement 1.2
    EncryptedOut[i] = en[i];

    if (DEBUG) {
      cout<< "EncryptedArray[" << i << "] = " << en[i] <<endl;
    }
    
    en_display[i] = ceil(fmod(en[i], CHECKSUM_SIZE));
  }
  
  EncryptedCheckSum = convertToString(en_display,lengthOfString);

  return writeIntoFile(en,EncryptedCheckSum, i);
}

/**
 * @brief 
 * 
 * A function to write the encrypted timestamp into a text file, as well as the checksum. It is part of the functional requirement 1
 * 
 * @param Content 
 * The content (in array of double) to be written into a file
 * @param checksum
 * The checksum of the timestamp string 
 * @param length 
 * The length of the content 
 * @return OperationState 
 * The operational state of writing the encrypted timestamp, as well as its checksum,  in a file.
 */
OperationState LicenseTimeStampOperation::writeIntoFile (double *Content, string checksum, size_t length) {

  if (EncryptionFileName.empty() || CheckSumFileName.empty()  || checksum.empty() || Content == nullptr || length == 0) {
    return INVALID_PARAMETER;
  }

  ofstream enfile (EncryptionFileName);
  if (enfile.is_open())
  {
    for(int count = 0; count < length; count++){
      enfile << setprecision(numeric_limits<double>::digits10 + 2) << Content[count] << endl ;
    }
   
    enfile.close();
  }
  else {
    cout << "Unable to open file, " << EncryptionFileName << endl;
    return FILE_FAIL_OPEN;
  }

  ofstream checksumFile (CheckSumFileName);

  if (checksumFile.is_open()) {
    checksumFile << checksum << endl;
    checksumFile.close();

  } else {
    cout << "Unable to open file, " << CheckSumFileName << endl;
    return FILE_FAIL_OPEN;
  }

  return SUCCESS;
}

/**
 * @brief 
 * 
 * A function to read the timestamp file 
 * 
 * @param Content
 * 
 * The container to hold the file read content
 *  
 * @param length 
 * 
 * The size of the read content (in an array of doubles)
 * @return OperationState 
 * 
 * The operational state of reading the encrypted timestamp, as well as its checksum,  from a file.
 */
OperationState LicenseTimeStampOperation::readFromFile (double* Content, size_t &length) {

  if (EncryptionFileName.empty() || CheckSumFileName.empty() || Content == nullptr) {
    return INVALID_PARAMETER;
  }

  // if the timestamp file does not exist, skip the rest of the function and return the corresponding error code - address the code test requirement 2.1
  if (!IsFileExists (EncryptionFileName) || !IsFileExists(CheckSumFileName)) {
    cout<<"license file does not exist for verification." << endl;
    return FILE_NOT_EXIST;
  }

  ifstream decfile(EncryptionFileName);
  
  int i = 0;

  if (decfile.is_open())
  {
    
    for (double a; decfile >> a;) {
      Content[i] = a;
      i++;
    }
    length = i;
    if (DEBUG) {
      cout << "length of the encrypted data is " << length << endl;
    }

    decfile.close();
  } else {
    cout << "Unable to open file, " << EncryptionFileName << endl;
    return FILE_FAIL_OPEN;
  }

  ifstream checksumfile (CheckSumFileName);
  string ReadChecksum = "";

  if (checksumfile.is_open()) {
         
    checksumfile >> ReadChecksum;
    checksumfile.close();

  } else {
    return FILE_FAIL_OPEN;
  }

  long int calculatedCheckSum [SIZE];

  for (i=0;i < length; i++) {
    calculatedCheckSum[i] = ceil(fmod(Content[i], CHECKSUM_SIZE));
  }

  string StrCalculatedCheckSum = convertToString(calculatedCheckSum,length);

  // if the timestamp file cannot be decrypted correctly with the expected checksum,  return the corresponding error code - address the code test requirement 2.2
  if (StrCalculatedCheckSum != ReadChecksum) {
    cout << "calculated: " << StrCalculatedCheckSum << ", read checksum: "<< ReadChecksum << endl;
    cout << "mismatched checksum. The license file has been tampered with."<< endl;
    return TIMESTAMP_TAMPERED;
  }

  return SUCCESS;

 }
 /**
  * @brief 
  * The API to inspect the timestamp.
  * 
  * An API to address the code test requirement 3.
  * 
  * @param outStr 
  * 
  * The otuput timestamp in string format.
  * 
  * @return OperationState 
  * 
  * The operational state of timestamp inspection.
  */

OperationState LicenseTimeStampOperation::InspectTimeStamp(string &outStr)
{
  OperationState ret = SUCCESS;

  int i;

  double localen[SIZE];
  size_t length;

  if ((ret = readFromFile (localen,length)) != SUCCESS) {
    outStr = "";
    return ret;
  }

 

  double decryptedMsg[SIZE];

  long int de_display[SIZE];

  double N = 1.0;

  for (i=0;i < length; i++){
    double privateKey = GetPrivateKey(i,N);
    
    cout << "Inspect timestamp: N[" << i << "] = " << N << endl;
    
    decryptedMsg[i] = pow(localen[i], privateKey);

   // cout << "decrypted[" << i << "]=" << decryptedMsg[i] << endl;

    decryptedMsg[i] = fmod(decryptedMsg[i],N);

    de_display[i] = ceil(decryptedMsg[i]);

    char temp = de_display[i];

    cout << "fmod[" << i << "]=" << temp << " ,length = " << length << endl;

    
  }

  outStr = convertASCIIToString(de_display,i);

  return ret;
}

/**
 * @brief 
 *  A function to convert the timestamp in string to that in time_t object
 * @param dateTime 
 * The targer timestamp string
 * @return time_t 
 * The converted time_t object
 */

time_t String2DateTime(string dateTime)
{

  tm ltm;

  // empty dataTime string handling.
  if (dateTime.empty()) {
    ltm.tm_year = 0; 
    ltm.tm_mon =  0;  
    ltm.tm_mday = 0; 
    ltm.tm_hour = 0; 
    ltm.tm_min =  0; 
    ltm.tm_sec =  0; 
    return mktime(&ltm);
  } 

  int n = dateTime.length();
 
  // declaring character array
  char char_array[n + 1];
 
  // copying the contents of the
  // string to char array
  strcpy(char_array, dateTime.c_str());

  char* pch;
  pch = strtok(char_array, "TZ-:");
  ltm.tm_year = atoi(pch) - 1900; //get the year value
  ltm.tm_mon = atoi(strtok(NULL, "TZ-:")) - 1;  //get the month value
  ltm.tm_mday = atoi(strtok(NULL, "TZ-:")); //get the day value
  ltm.tm_hour = atoi(strtok(NULL, "TZ-:")); //get the hour value
  ltm.tm_min = atoi(strtok(NULL, "TZ-:")); //get the min value
  ltm.tm_sec = atoi(strtok(NULL, "TZ-:")); //get the sec value

  if (DEBUG) {
    cout << "Year: "<< ltm.tm_year << endl;
    cout << "Month: "<< ltm.tm_mon<< endl;
    cout << "Day: "<< ltm.tm_mday << endl;
    cout << "Time: "<< ltm.tm_hour << ":";
    cout << ltm.tm_min << ":";
    cout << ltm.tm_sec << endl;
  }

  // Convert the tm structure to time_t value and return.
  return mktime(&ltm);

}

/**
 * @brief 
 * An API to check if the timestamp has expired - address code test requirement 2
 * 
 * @return true 
 * The timestamp has expired
 * @return false 
 * The tiestamp has not expired
 */

bool LicenseTimeStampOperation::IsTimeStampExpired() {

  bool ret  = true;
  string InputDateTime = "";
  OperationState state;

  // all the state check required in code test requirement 2 are included in this function call.
  if ((state = InspectTimeStamp(InputDateTime)) != SUCCESS) {
    return ret;
  }
  //  the timestamp was not initialized from the pevious functional call, assuming that operational failure, return true for time expiry.
  if (InputDateTime.empty()) {
    return ret;
  }
  //get the current time
  system_clock::time_point now_time = system_clock::now();
  time_t NowTime = system_clock::to_time_t(now_time);

  // convert the license start time into the time_t object for comparison.
  time_t StartTime = String2DateTime(InputDateTime);
  
  // If both the current time and the license start time are retrieved successfully, compare their time differences in days
  if ( NowTime != (time_t)(-1) && StartTime != (time_t)(-1)){
      
    double difference = difftime(NowTime, StartTime) / (60 * 60 * 24);
    
    if (DEBUG) {
      cout <<"Licnese Start Time: " <<ctime(&StartTime) << endl;
      cout <<"Now time: " <<ctime(&NowTime) << endl;
    }
    
    // print the license duration (in days), compared to the elapsed time (in days) 
    cout <<"License Duration: " << LicenseDurationInDays << " days" << endl;
    cout << "Elapsed days: " << difference << " days" << endl;
    
    ret = difference > LicenseDurationInDays || difference < 0;
  }

  return ret;

 }
 /**
  * @brief 
  * A function to convert a time_t object to a string
  * 
  * @param dateString 
  * The converted string for the current time_t object
  * @return OperationState 
  * The operational state of timestamp type conversion
  */

OperationState LicenseTimeStampOperation::ConvertcurrentDateToString(string &dateString)
{
  system_clock::time_point now_time = system_clock::now();

  time_t now = system_clock::to_time_t(now_time);

  tm *ltm = localtime(&now);

  if (ltm == nullptr) {
    cout << " failed to read the system time" << endl;
    return TIMESTAMP_RETRIEVAL_ERROR;
  }

  dateString = "";
  string tmp = "";
  tmp = to_string(1900 + ltm->tm_year);
  dateString += tmp;
  dateString += "-";

  tmp = to_string(1 + ltm->tm_mon);
  if (tmp.length() == 1) {
    tmp.insert(0, "0");
  }
  
  dateString += tmp;
  dateString += "-";

  tmp = to_string(ltm->tm_mday);
  if (tmp.length() == 1) {
    tmp.insert(0, "0");
  }
  
  dateString += tmp;
  dateString += "T";

  tmp = to_string(ltm->tm_hour);
  if (tmp.length() == 1) {
    tmp.insert(0, "0");
  }
  
  dateString += tmp;
  dateString += ":";

  tmp = to_string(ltm->tm_min);
  if (tmp.length() == 1) {
    tmp.insert(0, "0");
  }
  
  dateString += tmp;
  dateString += ":";
    
  tmp = to_string(ltm->tm_sec);
  
  if (tmp.length() == 1) {
    tmp.insert(0, "0");
  }
  
  dateString += tmp;
  dateString += "Z";

  return SUCCESS;

}