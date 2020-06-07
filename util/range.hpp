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

#include <algorithm>

template <class TT>
class Range {
public:
    TT from;
    TT to;
    
    bool contains(TT item) const {
        return from <= item && item <= to;
    }
    bool above(TT item) const {
        return item < from;    // range is above item
    }
    bool below(TT item) const {
        return item > to;    // range is below item
    }
    
    Range() {
        from = 0;
        to = 0;
    }
    Range(TT _from, TT _to = 0) {
        from = _from;
        to = std::max(_from, _to);
    }
    /*
    bool operator<(const Range& other) const  {
        return other.from < other.from;
    }
     */
};

/*
template <class TT>
struct CmpRange  {
    bool operator() (const Range<TT>& lhs, const Range<TT>& rhs) const {
        return lhs.from < rhs.from || (lhs.from == rhs.from && lhs.to < rhs.to);
    }
};
*/
template <class TT>
bool operator< (const Range<TT>& lhs, const Range<TT>& rhs)
{
    return lhs.from < rhs.from || (lhs.from == rhs.from && lhs.to < rhs.to);
}
/*
template <class TT>
bool operator<(const Range<TT>& lhs, TT rhs) { return lhs.from < rhs; }
template <class TT>
bool operator<(TT lhs, const  Range<TT>& rhs) { return lhs < rhs.from; }
*/
