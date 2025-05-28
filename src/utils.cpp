#include "utils.h"
#include <vector>

bool chkNumber(const string& str){
   return !str.empty() &&
   (str.find_first_not_of("[0123456789]") == std::string::npos);
}
// Function to split string str using given delimiter
vector<string> split(const string& str, char delim){
   auto i = 0;
   vector<string> list;
   auto pos = str.find(delim);
   while (pos != string::npos){
      list.push_back(str.substr(i, pos - i));
      i = ++pos;
      pos = str.find(delim, pos);
   }
   list.push_back(str.substr(i, str.length()));
   return list;
}
// Function to validate an IP address
bool validateIP(string ip){
   // split the string into tokens
   vector<string> slist = split(ip, '.');
   // if token size is not equal to four
   if (slist.size() != 4)
      return false;
   for (string str : slist){
      // check that string is number, positive, and range
      if (!chkNumber(str) || stoi(str) < 0 || stoi(str) > 255)
         return false;
   }
   return true;
}
