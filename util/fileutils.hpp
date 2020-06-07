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

#include <regex>
#include <queue>
#include "lstring.hpp"
#include "directory.hpp"


// Forward
typedef std::vector<std::regex> PatternList;
typedef std::vector<lstring> StringList;
typedef std::queue<lstring> FileDirList;
lstring& getName(lstring& outName, const lstring& inPath);
const lstring& getCwd();

// Extract parts of file path.
//    %#.#s    s=fullpath,  p=path only, n=name only, e=extension only f=filename name+ext
//    %0#d     o=offset,  l=length
// getParts("%n", filepath, outStr);
const char* getParts( const char* customFmt,  const char* filepath, std::vector<char>& buf);

template <typename TT>
class FileUtils {
public:
    typedef TT (*OnFile)(const lstring& fullname, FileUtils& fileUtils);
    
    FileUtils(OnFile _onFile, void* _stuff) : onFile(_onFile), stuff(_stuff) {
    }
    
private:
    size_t ScanFile(const lstring& fullname);
    OnFile onFile;
    
    lstring startDir;

public:
    void* stuff;
    
    PatternList includeFilePatList;
    PatternList excludeFilePatList;
    FileDirList fileDirList;
     
    size_t ScanFiles(const lstring& dirname);
};
