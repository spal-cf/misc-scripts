#!/bin/bash

set -v

app_binary=Skylight 

objection -g $app_binary run env

objection -g $app_binary run ios info binary

objection -g $app_binary run ios bundles list_frameworks

objection -g $app_binary run ios cookies get

objection -g $app_binary run ios nsuserdefaults get

objection -g $app_binary run ios nsurlcredentialstorage dump

objection -g $app_binary run ios keychain dump

# ios hooking search classes jail
# objection -d -g $app_binary explore -s "ios hooking set return_value \"+[JailbreakDetector isDeviceJailBroken]\" false"
