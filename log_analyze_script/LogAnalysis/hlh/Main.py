'''
Created on 2016-3-18

@author: vergil
'''
import os, sys, signal
from subprocess import call, PIPE, Popen
from LogAnalyzer import Analyzer

analyzer = Analyzer()

if __name__ == '__main__':
    apkName = sys.argv[1]
    print(apkName)
    if (apkName.endswith(".apk") == False):
        print("No a valid apk file!")
        exit(0)
    logfile = open('log.txt', 'w')
    logfile.close()
    call(['adb', 'logcat', '-c'])
    adb = Popen(['adb', 'logcat', '-s', 'AppanalyTag', os.path.dirname(os.path.realpath(__file__)) + '\log.txt'], stdin=PIPE, stdout=PIPE)
    ret = call(['monkeyrunner', 'MonkeyRunner.py', apkName], stderr=PIPE, cwd=os.path.dirname(os.path.realpath(__file__)))
    print("Now please start running the app and input \"exit\" exit!")
    while 1:
        command = input('>>')
        if command == 'exit':
            os.kill(adb.pid, signal.SIGTERM)
            analyzer.loadLogFile('log.txt')
            fileName = os.path.splitext(apkName)[0] + '.xml'
            report = analyzer.createXML()
            report.write(fileName, 'UTF-8')
            break
    print("Please check the generated xml file and remove the application")