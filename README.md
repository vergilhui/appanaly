version 1.0
NOTICE: ONLY FOR ANDROID EMULATOR, THERE MAY BE SOME PROBLEM IN REAL DEVICE!
android application behavior analysis

directory kernelimage is kernel image of android-goldfish-3.4.
directory module is the LKM file that hook android kernel syscall monitor android application behavior.
directory usr_netlink is the client that receive massage from android kernel LKM.

if you want to compile all the file, you should hava a android cross-compiler tool(android SDK is necessary).
this may help you get the executable file.

How to use:
1. Open an android emulator.
2. Push the executable file to android emulator by android adb tool.
   adb push <your-executable-file-path> <android-emulator-path>
3. Load the LKM to android emulator kernel and setup the userspace executable file(usr_netlink) by adb tool
   adb shell
   cd <android-emulator-path>
   insmod module_main.ko
   ./usr_netlink
4. Now you can run android application and your shell should get some log.

I am a beginner. If you find some error, you can contact me. My email address is vergilhlh@gmail.com. Of course,
fork is welcome!