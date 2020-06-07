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

#include "fileutils.hpp"


#ifdef WIN32
const char SLASH_CHAR('\\');
#else
const char SLASH_CHAR('/');
#endif

typedef FileUtils<size_t> FileUtils_sz;

// ---------------------------------------------------------------------------
// Extract name part from path.
lstring& getName(lstring& outName, const lstring& inPath)
{
    size_t nameStart = inPath.rfind(SLASH_CHAR) + 1;
    if (nameStart == 0)
        outName = inPath;
    else
        outName = inPath.substr(nameStart);
    return outName;
}

 // ---------------------------------------------------------------------------
 // Get Current Working Directory
const lstring& getCwd() {
   static lstring cwd;
   if (cwd.empty()) {
       char cwdTmp[256];
       cwd = getcwd(cwdTmp, sizeof(cwdTmp));
       cwd += Directory_files::SLASH;
   }
   return cwd;
}

// ---------------------------------------------------------------------------
// Return true if inPath (filename part) matches pattern in patternList
bool FileMatches(const lstring& inName, const PatternList& patternList, bool emptyResult)
{
    if (patternList.empty() || inName.empty())
        return emptyResult;
    
    for (size_t idx = 0; idx != patternList.size(); idx++)
        if (std::regex_match(inName, patternList[idx]))
            return true;
    
    return false;
}

// ---------------------------------------------------------------------------
void strfmt(
        std::vector<char>& buf,
        int width,
        const char* fmt,
        const char* val) {
    size_t orgSize = buf.size();
    buf.resize(orgSize + width+1);
    int len = snprintf(buf.data()+orgSize, width+1, fmt, val);
    if (len > width) {
        buf.resize(orgSize + len+1);
        len = snprintf(buf.data()+orgSize, len+1, fmt, val);
    }
    buf.resize(orgSize + len);
    // buf.push_back('\0');
    // return buf.data();
}

// ---------------------------------------------------------------------------
const char* getParts(
        const char* customFmt,
        const std::string& filepath,
        std::vector<char>& buf)
{
    // Extract parts of file path.
    //    %s       s=fullpath,  p=path only, n=name only, e=extension only f=filename name+ext
    // getParts("%n", filepath, outStr);
    
    lstring itemFmt;
    
    char* fmt = (char*)customFmt;
    while (*fmt) {
        char c = *fmt;
        if (c != '%') {
            buf.push_back(c);
            fmt++;
        } else {
            int width = 1;
            itemFmt = "%s";
            char c = fmt[1];
            fmt+=2;
            
            switch (c) {
                case 's':   // s=fullpath (path + name + ext)
                    strfmt(buf, width, itemFmt, filepath.c_str());
                    break;
                case 'p':   //  p=path
                   strfmt(buf, width, itemFmt, Directory_files::parts(filepath, true, false, false).c_str());
                   break;
                case 'r':   // relative path
                    strfmt(buf, width, itemFmt, Directory_files::parts(filepath, true, false, false)
                           .replaceStr(getCwd(), "").c_str());
                    break;
                case 'n':   // n=name
                    strfmt(buf, width, itemFmt, Directory_files::parts(filepath, false, true, false).c_str());
                    break;
                case 'e':   // e=extension
                    strfmt(buf, width, itemFmt, Directory_files::parts(filepath, false, false, true).c_str());
                    break;
                case 'f':   // f=filename name+ext
                    strfmt(buf, width, itemFmt, Directory_files::parts(filepath, false, true, true).c_str());
                    break;
                case '\0':
                    fmt--;
                    break;
                default:
                    buf.push_back(c);
                    break;
            }
        }
    }
    
    buf.push_back('\0');
    return buf.data();
}


// ---------------------------------------------------------------------------
template<>
size_t FileUtils_sz::ScanFile(const lstring& fullname)
{
    size_t fileCount = 0;
    if (fullname.length() > startDir.length()) {
        lstring name = fullname.substr(startDir.length());
        // getName(name, fullname);
    
        if (!name.empty()
        && !FileMatches(name, excludeFilePatList, false)
        && FileMatches(name, includeFilePatList, true))
        {
            (*onFile)(fullname, *this);
        }
    }
   
   return fileCount;
}

// ---------------------------------------------------------------------------
template<>
size_t FileUtils_sz::ScanFiles(const lstring& dirOrPattern)
{
    size_t fileCount = 0;
    struct stat filestat;
    int statResult;
    
    try {
        statResult = stat(dirOrPattern, &filestat) ;
        if (statResult == 0 && S_ISREG(filestat.st_mode)) {
            fileCount += ScanFile(dirOrPattern);    // Regular file
            return fileCount;
        }
    }
    catch (exception ex)  {
       // Probably a pattern, let directory scan do its magic.
    }

    lstring dirname = dirOrPattern;
    if (statResult != 0 || !S_ISDIR(filestat.st_mode)) {
        std::regex anyWildcard("[?*]");
        std::smatch smatch;
        if (std::regex_search(dirOrPattern, smatch, anyWildcard)) {
            size_t pos = smatch.position();
            pos = dirOrPattern.rfind(Directory_files::SLASH, pos);
            dirname = dirOrPattern.substr(0, pos);
            lstring patStr = dirOrPattern.substr(pos);
            patStr.replaceStr(".", "[.]").replaceStr("*", ".*").replaceStr("?",".");
            includeFilePatList.push_back(std::regex(patStr));

        } else {
            lstring filename = Directory_files::parts(dirOrPattern, false, true, true);
            if (filename.length() != 0) {
                 includeFilePatList.push_back(std::regex(filename));
            }
            dirname = Directory_files::parts(dirOrPattern, true, false, false);
            if (dirname.empty()) {
                dirname = getCwd();
            }
        }
    }
    

    if (startDir.empty()) startDir = dirname;
    
    Directory_files directory(dirname);
    lstring fullname;
    while (directory.more())   {
       directory.fullName(fullname);
       if (directory.is_directory())  {
           fileCount += ScanFiles(fullname);    // Recurse into directory
       }
       else if (fullname.length() > 0)  {
           fileCount += ScanFile(fullname);    // Scan using pattern
       }
   }
   
   return fileCount;
}



