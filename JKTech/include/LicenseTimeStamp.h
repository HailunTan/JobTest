#ifndef __LicenseTimeStamp_H__
#define __LicenseTimeStamp_H__

#include <iostream>
#include <string>
#include <vector>
#include <tuple>
#include <list>

using namespace std;
/**
 * @brief 
 * The maximal length of the timestamp string in bytes
 * 
 */
const int SIZE = 21;
/**
 * @brief 
 * 
 * The upper limit of the checksum number for each byte in the timestamp message.
 * 
 * TODO: it is a design parameter, it shall be a prime number to minimize the collision of the checksum number of each byte. 
 *        What value shall be chosen is a design parameter to be discussed.
 * 
 */
const int CHECKSUM_SIZE = 3001;
/**
 * @brief 
 * 
 * A boolean flag value to indicate whether the debug message shall be printed out to the console.
 * @true:  The debug messages will be printed out to the console.
 * @false: The debug messages will not be printed out to the console.
 */
const bool DEBUG = true;

typedef vector< tuple<double,double> > prime_list;

/**
 * @brief 
 * The enumeration to define the operation state in this library:
 * 
 * @SUCCESS: The operation is executed without any errors
 * @INVALID_PARAMETER: The operation contains invalid input parameter(s). So it cannot be executed.
 * @FILE_FAIL_OPEN: The operation needs to open a file. which fails to be opened.
 * @FILE_NOT_EXIST: The operation cannot be executed due to the missing file(s). It happened when the decryption of the timestamp file cannot find the file.
 * @FILE_EXIST: The operation cannot be executed because  the file(s) exist. It happened when the timestamp encryption found an existing encrypted timestamp file is available.
 */

enum OperationState {
      SUCCESS,
      INVALID_PARAMETER,
      FILE_FAIL_OPEN,
      FILE_NOT_EXIST,
      FILE_EXIST,
      TIMESTAMP_RETRIEVAL_ERROR,
      TIMESTAMP_TAMPERED
};

class LicenseTimeStampOperation
{
public:
 
  LicenseTimeStampOperation(string encryptionFileName, string CheckSumFileName, double LicenseDuration);
  OperationState CreateTimeStampFile(double* EncryptedOut,string &Encrypteddisplay);
  OperationState InspectTimeStamp(string &outStr);
  bool IsTimeStampExpired();
  const char* OperationStateToString(OperationState v);

private:
  prime_list PrimeList;
  OperationState ConvertcurrentDateToString(string &outStr);
  double GetPublicKey(int index);
  double GetPrivateKey(int index, double &N);
  string EncryptionFileName;
  string CheckSumFileName;
  double LicenseDurationInDays;
  OperationState writeIntoFile (double *Content, string hashCode, size_t length);
  OperationState readFromFile (double* Content, size_t &length);

};

#endif