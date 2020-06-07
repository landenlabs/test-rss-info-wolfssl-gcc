
# CXX = clang++
CXX = g++
CXXFLAGS = -std=c++11

debug=1

ifeq ($(OS),Windows_NT)
platform=windows
else
ifeq ($(shell uname -s),Linux)
platform=linux
endif
ifeq ($(shell uname -s),Darwin)
platform=macos
endif
ifeq ($(shell uname -s),Haiku)
platform=haiku
endif
endif

CXXFLAGS=-c -std=c++11 -Wall -O2 -I../include -I./util 
LDFLAGS=-O2 -lwolfssl -lnetwork
ifeq ($(platform),haiku)
LDFLAGS+=-lwolfssl -lnetwork
endif

ifeq ($(debug),1)
all: CXXFLAGS+=-DDEBUG -g
endif

TEST_SRC=test.cpp
TEST_BASE=$(basename $(TEST_SRC))
TEST_OBJ=$(TEST_BASE:=.o)

GET_RSS_SRC=get-rss.cpp
GET_RSS_BASE=$(basename $(GET_RSS_SRC))
GET_RSS_OBJ=$(GET_RSS_BASE:=.o)

LOAD_XML_SRC=load-xml.cpp pugixml.cpp util/directory.cpp util/fileutils.cpp HTTPSRequest.cpp
LOAD_XML_BASE=$(basename $(LOAD_XML_SRC))
LOAD_XML_OBJ=$(LOAD_XML_BASE:=.o)

all: test get-rss load-xml connect1 connect2

test: $(TEST_OBJ)
	$(CXX) $(TEST_OBJ) $(LDFLAGS) -o $@

get-rss: $(GET_RSS_OBJ)
	$(CXX) $(GET_RSS_OBJ) $(LDFLAGS) -o $@

load-xml: $(LOAD_XML_OBJ)
	$(CXX) $(LOAD_XML_OBJ) $(LDFLAGS) -o $@

connect1: connect1.o
	$(CXX) connect1.o $(LDFLAGS) -o $@

connect2: connect2.o
	$(CXX) connect2.o $(LDFLAGS) -o $@

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $< -o $@

.PHONY: clean
clean:
ifeq ($(platform),windows)
	-del /f /q "test.exe" "*.o"
else
	$(RM)  *.o  test get-rss load-xml
endif