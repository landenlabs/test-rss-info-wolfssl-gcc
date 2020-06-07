//-------------------------------------------------------------------------------------------------
//
//  llcsv      4/20/2020       Dennis Lang
//
//  CSV command line tool
//
//-------------------------------------------------------------------------------------------------
//
// Author: Dennis Lang - 2020
// http://landenlabs.com/
//
// This file is part of llcsv project.
//
// ----- License ----
//
// Copyright (c) 2020 Dennis Lang
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.


#pragma once

#include <string>
#include <regex>

namespace StrUtils {

 
inline
std::string& remove(std::string& str, const char* find) {
    while (*find) {
        size_t pos = str.find(*find++);
        if (pos != std::string::npos) {
            str.erase(pos, 1);
        }
    }
    return str;
}

inline
bool remove(std::string& str, std::regex& findRx) {
#if 0
    size_t orgLen = str.length();
    str =  std::regex_replace(str, findRx, "", std::regex_constants::format_first_only);
    return str.length() != orgLen;
#else
    std::smatch smatch;
    if (std::regex_match(str, smatch, findRx)) {
        size_t pos = smatch.position();
        size_t len = smatch[0].length();
        str.erase(pos, len);
        return true;
    }
    return false;
#endif
}

inline
std::string& removeWrapper(std::string& str, const char* find) {
    while (*find) {
        if (str[0] == *find++) {
            str.erase(0, 1);
            str.erase(str.length()-1, 1);
            break;
        }
    }
    return str;
}



inline
std::string& toUpper(std::string& inOut) {
    for (size_t idx = 0; idx < inOut.length(); idx++) {
        inOut[idx] = toupper(inOut[idx]);
    }
    return inOut;
}
inline
std::string& toLower(std::string& inOut) {
    for (size_t idx = 0; idx < inOut.length(); idx++) {
        inOut[idx] = tolower(inOut[idx]);
    }
    return inOut;
}
inline
std::string& toCapitalize(std::string& inOut) {
    bool isWord = true;
    for (size_t idx = 0; idx < inOut.length(); idx++) {
        char& c = inOut[idx];
        c = isWord ? tolower(c) : tolower(c);
        isWord = isspace(c);
    }
    return inOut;
}

inline
bool containsCase(const std::string& str, const std::string& val) {
    return strstr(str.c_str(), val.c_str()) != nullptr;
}
inline
bool containsNoCase(const std::string& str, const std::string& val) {
    return strcasestr(str.c_str(), val.c_str()) != nullptr;
}

inline
bool equalsCase(const std::string& str, const std::string& val) {
    return str == val;
}
inline
bool equalsNoCase(const std::string& str, const std::string& val) {
    return strcasecmp(str.c_str(), val.c_str());
}
 
inline
double toDbl(const std::string& str) {
    return strtod(str.c_str(), nullptr);
}

 
template<typename TT>
bool notEqualNum(TT srcVal, TT matVal) {
    return srcVal != matVal;
}
 
template<typename TT>
bool equalNum(TT srcVal, TT matVal) {
    return srcVal = matVal;
}
 
template<typename TT>
bool lessNum(TT srcVal, TT matVal) {
    return srcVal < matVal;
}
 
template<typename TT>
bool lessEqualNum(TT srcVal, TT matVal) {
    return srcVal <= matVal;
}
 
template<typename TT>
bool greaterNum(TT srcVal, TT matVal) {
    return srcVal > matVal;
}
 
template<typename TT>
bool greaterEqualNum(TT srcVal, TT matVal) {
    return srcVal >= matVal;
}
}
