#!/bin/bash

set -v

app_binary=com.amazon.workspaces 

objection -g $app_binary run env

objection -g $app_binary run android hooking list activities
objection -g $app_binary run android hooking list services
objection -g $app_binary run android hooking list receivers
objection -g $app_binary run android memory list modules

objection -g $app_binary run android keystore list
