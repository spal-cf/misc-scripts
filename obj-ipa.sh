#!/bin/bash

set -v

app_binary=<binary name> 

objection -g $app_binary run env
sleep 1
objection -g $app_binary run ios info binary
objection -g $app_binary run "ios bundles list_bundles --full-path"
objection -g $app_binary run ios bundles list_frameworks
objection -g $app_binary run ios nsuserdefaults get
objection -g $app_binary run ios nsurlcredentialstorage dump
objection -g $app_binary run ios plist cat Info.plist

objection -g $app_binary run "ios keychain dump --json keychain.json"
objection -g $app_binary run ios cookies get

objection -g $app_binary run  memory list exports

objection -g $app_binary run  "memory list modules --json modules.json"
sleep 1
objection -g $app_binary run ios hooking search classes cloudbi


##!/bin/bash
#
#set -v
#
#app_binary=com.google.cloudbi 
#echo exit | objection -g $app_binary explore  -c ios-obj-cmds.txt
