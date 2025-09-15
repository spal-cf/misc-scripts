/* activity_logger.js */
if (Java.available) {
    Java.perform(function() {
        console.log("Activity Logger: Hooking Activity.startActivity...");

        // Use Android's Activity.startActivity method to log activity launches.
        // There are multiple overloads, so we hook all of them.
        var Activity = Java.use("android.app.Activity");
        
        // Overload 1: startActivity(Intent)
        Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
            logIntent(intent);
            this.startActivity.overload('android.content.Intent').call(this, intent);
        };

        // Overload 2: startActivity(Intent, Bundle)
        Activity.startActivity.overload('android.content.Intent', 'android.os.Bundle').implementation = function(intent, options) {
            logIntent(intent);
            this.startActivity.overload('android.content.Intent', 'android.os.Bundle').call(this, intent, options);
        };

        // Helper function to log details of an Intent
        function logIntent(intent) {
            try {
                var component = intent.getComponent();
                if (component != null) {
                    var componentName = component.getClassName();
                    var action = intent.getAction();
                    var data = intent.getData();

                    console.log("\n[+] Activity Started:");
                    console.log("    Class Name: " + componentName);
                    console.log("    Action: " + action);
                    console.log("    Data: " + data);
                    console.log("    Extras: " + intent.getExtras());
                    console.log("------------------------");
                }
            } catch (e) {
                console.log("Error logging intent: " + e.message);
            }
        }
    });
} else {
    console.log("Java not available. This script is for Android.");
}
