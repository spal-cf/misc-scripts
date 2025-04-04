#!/bin/bash

set -v

app_binary=Skylight 

# PIC - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0228/
# Stack Canary - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0229/
# Canary and pic flags should be set to true

rabin2 -I $app_binary 2>/dev/null | grep -E "canary|nx|pic" 

# ARC - https://mas.owasp.org/MASTG/tests-beta/ios/MASVS-CODE/MASTG-TEST-0230/
# Expect some of the following symbols in result - objc_autorelease|objc_retainAutorelease|objc_release|objc_retain|swift_release|swift_retain|objc_retainAutoreleasedReturnValue

rabin2 -i Skylight 2>/dev/null | grep -E "objc_r|objc_a"

# https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0076/#wkwebview

rabin2 -zz ./Skylight 2>/dev/null | egrep "UIWebView"

rabin2 -zz ./Skylight 2>/dev/null | egrep "WKWebView"

rabin2 -zzq ./Skylight 2>/dev/null | egrep "WKWebView.*frame"

rabin2 -zz ./Skylight 2>/dev/null | grep -i "javascriptenabled"

rabin2 -zz ./Skylight 2>/dev/null | grep -i "hasonlysecurecontent"

# https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0077/#testing-how-webviews-load-content

rabin2 -zz ./Skylight 2>/dev/null | grep -i "loadHTMLString"

rabin2 -zz ./Skylight 2>/dev/null  | grep -i "loadFileURL"

# Testing deprecated methods
rabin2 -zzq Skylight 2>/dev/null | grep -i "openurl"


# https://mas.owasp.org/MASTG/tests/ios/MASVS-PLATFORM/MASTG-TEST-0075/#using-frida_1

grep -A 5 -nri LSApplicationQueriesSchemes Info.plist

grep -A 5 -nri urlsch Info.plist

grep -i CFBundleURLTypes -A25 Info.plist

ldid -e Skylight

# frida -U Skylight --codeshare mrmacete/objc-method-observer 
# observeSomething("*[* *openURL*]");
# in safari use url scheme

# Paste following
# function openURL(url) {
#                            var UIApplication = ObjC.classes.UIApplication.sharedApplication();
#                            var toOpen = ObjC.classes.NSURL.URLWithString_(url);
#                            return UIApplication.openURL_(toOpen);
#                        }
# [iOS Device::Skylight ]-> openURL("workspaces://?contactNumber=123456789&message=hola")


# https://gist.githubusercontent.com/grepharder/4b0724f56d7c451e240a38a7ddd56bc2/raw/69c99be65a331c4e2ae966c7f3fc9cfd6bc82fa0/urlschemefuzzer.js

# frida -U SpringBoard -l ios-url-scheme-fuzzing.js

# frida --codeshare dki/ios-url-scheme-fuzzing -U Skylight
# dumpSchemes();
# fuzz("workspaces://{0}");

