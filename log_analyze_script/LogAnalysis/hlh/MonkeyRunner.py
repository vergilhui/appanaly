'''
Created on 2016-3-18

@author: vergil
'''
import sys
from com.android.monkeyrunner import MonkeyRunner

apkName = sys.argv[1]
device = None

while device == None:
    try:
        print("Waiting for the device...")
        device = MonkeyRunner.waitForConnection(3)
    except:
        pass

print("Installing the application %s..." % apkName)
device.installPackage(sys.argv[1])
print("Installed!")