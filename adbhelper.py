from  adb import *

# Example usage
if __name__ == "__main__":
    #run_command("adb shell dumpsys package com.google.android.apps.cloud.cloudbi")
    #run_command("adb shell am start -W -n com.google.android.apps.cloud.cloudbi/.MainActivity")
    #run_command("adb shell am start -W -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d \"https://lookerstudio.google.com\" com.google.android.apps.cloud.cloudbi")
    #run_command("adb shell am start -a android.intent.action.MAIN -n com.google.android.apps.cloud.cloudbi/.MainActivity")
    pkg = run_command("aapt dump badging apks/base.apk|awk -F\" \" '/package/ {print $2}'|awk -F\"'\" '/name=/ {print $2}'")
    act = run_command("aapt dump badging apks/base.apk|awk -F\" \" '/launchable-activity/ {print $2}'|awk -F\"'\" '/name=/ {print $2}'")
    print (pkg)
    print(act)
    run_command("adb shell am start -W -n " + pkg + "/" + act) 
