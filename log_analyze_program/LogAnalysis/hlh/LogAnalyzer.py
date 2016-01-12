'''
Created on 2016-1-4

@author: vergil
'''
from _io import open
##from xml.etree.ElementTree import ElementTree
#from xml.etree.ElementTree import SubElement
#from xml.etree.ElementTree import Element
from xml.etree import cElementTree as ET
#from xml.etree.cElementTree import ElementTree
#from xml.etree.cElementTree import Element
#from xml.etree.cElementTree import SubElement
import json
import re
import codecs
import os

smslist = []
diallist = []
calllist = []
filelist = []

def parseCall(dictObj):
    """Parse dial message form parameter and store it into global variable
       calllist.
    
    Args:
        dictObj: dictionary object contains phone call message.
    """
    call = {'cmd': dictObj['callObject']['cmd'][0:3], 
            'number': dictObj['callObject']['cmd'][3:-1]}
    global calllist
    calllist.append(call)

def parseSms(dictObj):
    """Parse dial message form parameter and store it into global variable
       smslist.
    
    Args:
        dictObj: dictionary object contains sms message.
    """
    phoneLen = int(dictObj['smsObject']['sms'][6:8], 16)
    if phoneLen % 2 != 0:
        phoneLen += 1
    phoneNumCode = dictObj['smsObject']['sms'][10:phoneLen+10]
    phoneNum = decodePhoneNum(phoneNumCode)
    encoding = dictObj['smsObject']['sms'][phoneLen+10+2:phoneLen+10+2+2]
    msgCode = dictObj['smsObject']['sms'][phoneLen+10+4+2:]
    msg = ''
    if encoding == '00':
        msg = msg7bitDecode(msgCode)
    elif encoding == '08':
        msg = msgUCS2Decode(msgCode)
    sms = {'destnum': phoneNum, 'msg': msg}
    global smslist
    smslist.append(sms)
    
    
def parseFile(dictObj):
    """Parse dial message form parameter and store it into global variable
       filelist.
    
    Args:
        dictObj: dictionary object contains file operation message.
    """
    fileAction = {'type': dictObj['pvcObject']['type'],
                  'path': dictObj['pvcObject']['path'],
                  'action': dictObj['pvcObject']['action']}
    global filelist
    filelist.append(fileAction)
    
def parseDial(dictObj):
    """Parse dial message form parameter and store it into global variable
       diallist.
    
    Args:
        dictObj: dictionary object contains dial message.
    """
    dial = {'cmd': dictObj['dialObject']['cmd']}
    global diallist
    diallist.append(dial)
    
def decodePhoneNum(phoneNumCode):
    """Decode phone number form PDU format sms.
    
    Args:
        phoneNumCode: phone number part of PDU.
    
    Returns:
        the decoded phone number.
        example:
        
        5145497135f5
        15549417535
    """
    s = '';
    for i in range(0, len(phoneNumCode), 2):
        s += phoneNumCode[i + 1];
        s += phoneNumCode[i];
    if s.endswith('f'):
        s = s[:len(s)-1]
    return s

def msg7bitDecode(msgCode):
    """Decode the string encoded by 7bit coding.
    
    Args:
        msgCode: string encoded by 7bit coding.
        
    Returns:
        the decoded string.
    """
    msgCode = ''.join((re.findall(r'..', msgCode)[::-1]))
    r = ''
    d = int(msgCode, 16)
    while d:
        r += chr(d & 0x7f)
        d >>= 7
    return r

def msgUCS2Decode(msgCode):
    """Decode the string encoded by UCS2 coding.
    
    Args:
        msgCode: string encoded by UCS2 coding.
        
    Returns:
        the decoded string.
    """
    msgbs = msgCode.encode();
    msgrs = msgbs.decode();
    msgbs = codecs.decode(msgrs, 'hex_codec')
    msg = msgbs.decode('utf_16_be')
    return msg

def createXML(smslist, diallist, calllist, filelist):
    """Parse log file result, create xml and write the result to it.
    
    Args:
        smslist: short message list, each element of list is a dictionary object.
        diallist: dial message list, each element of list is a dictionary object.
        calllist: phone call message list, each element of list is a dictionary object.
        filelist: file operation message list, each element of list is a dictionary object.
    
    
    Returns:
        An ElementTree object which is created depending on the message in function
        parameters' list.
    """
    content = """
    <content>    
    </content>
    """
    root = ET.fromstring(content)
    if len(smslist) > 0:
        smslists = ET.Element('smslists')
        root.append(smslists)
        for e in smslist:
            lists = ET.Element('list')
            ET.SubElement(lists, 'destnum').text = e['destnum']
            ET.SubElement(lists, 'msg').text = e['msg']
            smslists.append(lists)
    
    if len(diallist) > 0:
        diallists = ET.Element('diallists')
        root.append(diallists)
        if len(calllist) > 0:
            for e in calllist:
                call = ET.Element('call')
                ET.SubElement(call, 'number').text = e['number']
                ET.SubElement(call, 'cmd').text = e['cmd']
                diallists.append(call)
        for e in diallist:
            lists = ET.Element('list')
            ET.SubElement(lists, 'cmd').text = e['cmd']
            diallists.append(lists)
    
    if len(filelist) > 0:
        filelists = ET.Element('filelists')
        root.append(filelists)
        for e in filelist:
            lists = ET.Element('list')
            ET.SubElement(lists, 'type').text = e['type']
            ET.SubElement(lists, 'path').text = e['path']
            ET.SubElement(lists, 'action').text = e['action']
            filelists.append(lists)
    indent(root)
    return ET.ElementTree(root)

def indent(elem, level=0):
    """Format XML file to pretty print.
    
    Args:
        elem: element of XML.
        level: level of element, default value is 0.
    """
    i = '\n' + level*'    '
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + '    '
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def loadLogFile(path):
    """load and parse log file.
    
    Args:
        path: log file path.
    """
    logf = open(path)
    for line in logf:
        npos = line.find('{')
        if npos >= 0:
            logObj = json.loads(line[npos:])
            if 'callObject' in logObj:
                parseCall(logObj)
            if 'smsObject' in logObj:
                parseSms(logObj)
            if 'dialObject' in logObj:
                parseDial(logObj)

if __name__ == '__main__':
    path = 'log.txt'
    loadLogFile(path)
    fileName = os.path.splitext(path)[0] + '.xml'
    report = createXML(smslist, diallist, calllist, filelist)
    report.write(fileName, 'UTF-8')