#!/bin/bash

set -v

Unzip cloudconsole.ipa
#cd Payloads
app_pkg=Vespa.app
app_binary=Vespa
binary_path=cloudconsole/Payload/$app_pkg/$app_binary
pkg_path=cloudconsole/Payload/$app_pkg

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



mkdir out

strings $binary_path > strings-analytics.txt

grep -ri shell strings-analytics.txt --color=always > out/shell.txt
grep -ri api strings-analytics.txt --color=always > out/api.txt
grep -ri database strings-analytics.txt --color=always > out/database.txt
grep -ri query strings-analytics.txt --color=always > out/query.txt
grep -ri post strings-analytics.txt --color=always > out/post.txt
grep -ri get strings-analytics.txt --color=always > out/get.txt
grep -ri config strings-analytics.txt --color=always > out/config.txt
grep -ri auth strings-analytics.txt --color=always > out/auth.txt
grep -ri password strings-analytics.txt --color=always > out/password.txt
grep -ri singleton strings-analytics.txt --color=always > out/singleton.txt
grep -ri secret strings-analytics.txt --color=always > out/secret.txt
grep -ri http strings-analytics.txt --color=always > out/http.txt
grep -ri https: strings-analytics.txt --color=always > out/http.txt


grep -i UsageDescription -A25 $pkg_path/Info.plist
grep -i NSAppTransportSecurity $pkg_path/Info.plist
grep -i UTExportedTypeDeclarations $pkg_path/Info.plist
grep -i UTImportedTypeDeclarations $pkg_path/Info.plist
grep -i CFBundleURLTypes -A25 $pkg_path/Info.plist



getCryptAlgorithmClass
getCryptAlgorithmType

# https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/#wkwebview

rabin2 -zz $binary_path | egrep "UIWebView$"
rabin2 -zz $binary_path | egrep "WKWebView$"
rabin2 -zzq $binary_path | egrep "WKWebView.*frame"
rabin2 -zz $binary_path | grep -i "javascriptenabled"
rabin2 -zz $binary_path | grep -i "hasonlysecurecontent"

# https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077/#testing-how-webviews-load-content

rabin2 -zz $binary_path | grep -i "loadHTMLString"
rabin2 -zz $binary_path | grep -i "loadFileURL"

# Testing deprecated methods
rabin2 -zzq $binary_path 2>/dev/null | grep -i "openurl"

rabin2 -zq $binary_path 2>/dev/null | grep -i "activityitems"


# https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/#using-frida_1

grep -A 5 -nri LSApplicationQueriesSchemes $pkg_path/Info.plist

grep -A 5 -nri urlsch $pkg_path/Info.plist

grep -i CFBundleURLTypes -A25 $pkg_path/Info.plist


rabin2 -I $binary_path


otool -L $binary_path

otool -L $binary_path | grep -i LocalAuthentication

cat $pkg_path/Info.plist

#dumps the binary's entitlements

ldid -e $binary_path > ent.xml

codesign -dv $binary_path

dsymutil -s $binary_path | grep N_OSO


# assuming you have extracted the entitlements to ent.xml
doms=$(plutil -extract com.apple.developer.associated-domains xml1 -o - ent.xml | \
       grep -oE 'applinks:[^<]+' | cut -d':' -f2)
for d in $doms; do
  echo "[+] Fetching AASA for $d";
  curl -sk "https://$d/.well-known/apple-app-site-association" | jq '.'
done
