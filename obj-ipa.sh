#!/bin/bash

set -v

app_binary=<binary name> 

objection -g $app_binary run env
objection -g $app_binary run ios info binary
objection -g $app_binary run ios bundles list_frameworks
objection -g $app_binary run ios nsuserdefaults get
objection -g $app_binary run ios nsurlcredentialstorage dump
objection -g $app_binary run ios plist cat Info.plist

objection -g $app_binary run ios keychain dump
objection -g $app_binary run ios cookies get

objection -g $app_binary run  memory list modules

objection -g $app_binary run ios hooking search classes cloudbi
