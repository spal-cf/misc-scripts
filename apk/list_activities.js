Java.perform(function() {
    try {
        var ActivityManager = Java.use('android.app.ActivityManager');
        var Context = Java.use('android.content.Context');

        // Get the current application context
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        var context = currentApplication.getApplicationContext();

        // Get an instance of ActivityManager
        var activityManager = Java.cast(context.getSystemService(Context.ACTIVITY_SERVICE.value), ActivityManager);

        // Get the list of running tasks
        var runningTasks = activityManager.getRunningTasks(100); // Get up to 100 tasks

        console.log("[*] Listing Running Activities:");
        for (var i = 0; i < runningTasks.size(); i++) {
            var taskInfo = runningTasks.get(i);
            var baseActivity = taskInfo.baseActivity.getClassName();
            var topActivity = taskInfo.topActivity.getClassName();
            var packageName = taskInfo.baseActivity.getPackageName();

            console.log("  Package: " + packageName);
            console.log("    Base Activity: " + baseActivity);
            console.log("    Top Activity: " + topActivity);
            console.log("-----------------------------------");
        }

    } catch (e) {
        console.log("Error: " + e);
    }
});
