appanaly
==========================
**NOTICE: ONLY AVAILABLE IN LINUX** 
**NOTICE: ONLY FOR ANDROID EMULATOR, THERE MAY BE SOME PROBLEM IN REAL DEVICE!**  
android application behavior analysis  
directory kernelimage is kernel image of android-goldfish-3.4.  
directory module is the LKM file that hook android kernel syscall monitor android application behavior.  
directory usr_netlink is the client that receive massage from android kernel LKM.  

if you want to compile all the file, you should hava a android cross-compiler tool(android SDK is necessary).  
this may help you get the executable file.

###	How to use:
1. Open an android emulator.  
* Push the executable file to android emulator by android adb tool.  
```Bash
adb push <your-executable-file-path> <android-emulator-path>
```
* Load the LKM to android emulator kernel and setup the userspace executable file(usr_netlink) by adb tool  
```Bash
adb shell
cd <android-emulator-path>
insmod module_main.ko
./usr_netlink
```
* Push your apk file to the log_analyze_script_/LogAnalysis/hlh and open this directory in your shell and run the Main.py.
```Bash
python3 Main.py your-apk-file.apk
```
* if you type "exit" command, you can go to the directory and the analysis result will be there(a xml file).
* Now you can run android application and your shell should get some log.  
I am a beginner. If you find some error, you can contact me. My email address is vergilhlh@gmail.com. Of course,  
fork is welcome!