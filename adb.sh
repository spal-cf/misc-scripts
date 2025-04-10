
apksigner verify -v --print-certs base.apk

# https://mas.owasp.org/MASTG/tests-beta/android/MASVS-STORAGE/MASTG-TEST-0262/

find ./ -name AndroidManifest.xml
find ./ -name data_extraction_rules.xml 
find ./ -name backup_rules.xml 
grep -i backup AndroidManifest.xml 
grep -i fullBackupContent AndroidManifest.xml 
grep -i dataExtractionRules AndroidManifest.xml

content query --uri content://media/external/file --projection _data | grep -i workspaces

ps -ef | grep workspaces

lsof -p <pid>

# https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0116/

apksigner verify --verbose example.apk

apksigner verify --print-certs --verbose example.apk

aapt d badging MASTG-DEMO-0001.apk

apktool d myapp.apk -s -o apktooled_app

# https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0115/

for i in $(ls lib/x86_64/); do echo $i; rabin2 -I lib/x86_64/$i | grep -E "canary


adb shell dumpsys package com.amazon.workspaces

adb shell dumpsys meminfo > mem.txt

adb shell am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d "workspaces://test" com.amazon.workspaces

adb shell am start -W -n com.amazon.workspaces/crc64047a0d770568f918.MainActivity

adb shell am start -a android.intent.action.MAIN -n com.amazon.workspaces/crc64047a0d770568f918.MainActivity

pkg=$(aapt dump badging $1|awk -F" " '/package/ {print $2}'|awk -F"'" '/name=/ {print $2}')
act=$(aapt dump badging $1|awk -F" " '/launchable-activity/ {print $2}'|awk -F"'" '/name=/ {print $2}')
adb shell am start -n $pkg/$act

# adb-run.sh myapp.apk

# https://github.com/inesmartins/Android-App-Link-Verification-Tester/tree/main
