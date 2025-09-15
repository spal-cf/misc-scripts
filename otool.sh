#!/bin/bash

set -v

app_pkg=GoogleAnalytics.app
app_binary=GoogleAnalytics
binary_path=$app_pkg/$app_binary 

# Checking PIE (Position Independent Executable) - It should include the PIE flag
# PIC - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0228/

otool -hv $binary_path | grep PIE

# Checking Stack Canaries - It should include the symbols: stack_chk_guard and stack_chk_fail
# Stack Canary - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0229/

otool -I -v $binary_path | grep stack_chk

# Checking ARC (Automatic Reference Counting) - It should include the _objc_release symbol
# ARC - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0230/

otool -I -v $binary_path | grep -E "objc_autorelease|objc_retainAutorelease|objc_release|objc_retain|swift_release|swift_retain|objc_retainAutoreleasedReturnValue"

#Checking Encrypted Binary - The cryptid should be 1
otool -arch all -Vl $binary_path | grep -A5 LC_ENCRYPT

#Checking Weak Hashing Algorithms
otool -Iv $binary_path | grep -w "_CC_MD5"
otool -Iv $binary_path | grep -w "_CC_SHA1"

# Checking Insecure Random Functions
otool -Iv $binary_path | grep -w "_random"
otool -Iv $binary_path | grep -w "_srand"
otool -Iv $binary_path | grep -w "_rand"

# Checking Insecure malloc Function
otool -Iv $binary_path | grep -w "_malloc"

# Checking Insecure and Vulnerable Functions
otool -Iv $binary_path | grep -w "_gets"
otool -Iv $binary_path | grep -w "_memcpy"
otool -Iv $binary_path | grep -w "_strncpy"
otool -Iv $binary_path | grep -w "_strlen"
otool -Iv $binary_path | grep -w "_vsnprintf"
otool -Iv $binary_path | grep -w "_sscanf"
otool -Iv $binary_path | grep -w "_strtok"
otool -Iv $binary_path | grep -w "_alloca"
otool -Iv $binary_path | grep -w "_sprintf"
otool -Iv $binary_path | grep -w "_printf"
otool -Iv $binary_path | grep -w "_vsprintf"


otool -L $binary_path
otool -L $binary_path | grep -i LocalAuthentication

ldid -e $binary_path
