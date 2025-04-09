import sys
import frida

def on_message(message, data):
    print ("[%s] -> %s" % (message, data))

def main(target_process):
	session = frida.get_usb_device().attach(target_process)
	script = session.create_script("""
		/* 
    Description: Android Decrypt AES data
    Usage: frida -U -f XXX -l android-aes-decrypt-no-iv.js
    Credit: @entdark_

    Links:
        https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec
        https://developer.android.com/reference/javax/crypto/Cipher
*/

function byteArrayToString(arrayBuffer) 
{
    return String.fromCharCode.apply(null, new Uint8Array(arrayBuffer));
}

Java.perform(() => 
{
    const secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');

    secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) 
    {
        console.log('key:' + byteArrayToString(key));
        console.log('algo:' + algo);
        return this.$init(key, algo);
    };

    const cipher = Java.use('javax.crypto.Cipher')['doFinal'].overload('[B').implementation = function(byteArray) 
    {
        console.log('encode:' + byteArrayToString(byteArray));
        return this.doFinal(byteArray);
    };
});
""")

	script.on('message', on_message)
	script.load()
	input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
	session.detach()

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print ('Usage: %s <process name or PID>' % __file__)
		sys.exit(1)

	try:
		target_process = int(sys.argv[1])
	except ValueError:
		target_process = sys.argv[1]

	main(target_process)
