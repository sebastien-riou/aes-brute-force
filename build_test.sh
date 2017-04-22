#!/bin/sh

baseDir=.
testDir=$baseDir/test
includeDir=$baseDir/include

if [ -z ${CXX+x} ]; then CXX=c++; fi

$CXX -Ofast -Wall -march=native -std=c++11 $testDir/aes-brute-force.cpp -I $includeDir -o aes-brute-force -lpthread $*
