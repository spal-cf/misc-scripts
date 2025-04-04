#!/bin/bash

set -v

app_binary=Skylight 

# Checking PIE (Position Independent Executable) - It should include the PIE flag
# PIC - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0228/

otool -hv $app_binary | grep PIE

# Checking Stack Canaries - It should include the symbols: stack_chk_guard and stack_chk_fail
# Stack Canary - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0229/

otool -I -v $app_binary | grep stack_chk

# Checking ARC (Automatic Reference Counting) - It should include the _objc_release symbol
# ARC - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0230/

otool -I -v $app_binary | grep -E "objc_autorelease|objc_retainAutorelease|objc_release|objc_retain|swift_release|swift_retain|objc_retainAutoreleasedReturnValue"

#Checking Encrypted Binary - The cryptid should be 1
otool -arch all -Vl $app_binary | grep -A5 LC_ENCRYPT

#Checking Weak Hashing Algorithms
otool -Iv $app_binary | grep -w "_CC_MD5"
otool -Iv $app_binary | grep -w "_CC_SHA1"

# Checking Insecure Random Functions
otool -Iv $app_binary | grep -w "_random"
otool -Iv $app_binary | grep -w "_srand"
otool -Iv $app_binary | grep -w "_rand"

# Checking Insecure malloc Function
otool -Iv $app_binary | grep -w "_malloc"

# Checking Insecure and Vulnerable Functions
otool -Iv $app_binary | grep -w "_gets"
otool -Iv $app_binary | grep -w "_memcpy"
otool -Iv $app_binary | grep -w "_strncpy"
otool -Iv $app_binary | grep -w "_strlen"
otool -Iv $app_binary | grep -w "_vsnprintf"
otool -Iv $app_binary | grep -w "_sscanf"
otool -Iv $app_binary | grep -w "_strtok"
otool -Iv $app_binary | grep -w "_alloca"
otool -Iv $app_binary | grep -w "_sprintf"
otool -Iv $app_binary | grep -w "_printf"
otool -Iv $app_binary | grep -w "_vsprintf"

