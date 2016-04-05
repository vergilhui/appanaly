'''
Created on 2016-1-4

@author: vergil
'''
from _io import open
from xml.etree import cElementTree as ET
import json
import re
import codecs

class Analyzer:
    
    def __init__(self):
        self.smslist = []
        self.diallist = []
        self.calllist = []
        self.filelist = []
        self.netlist = []
    
    def __parseCall(self, callObj):
        """Parse dial message form parameter and store it calllist of the member variable.
        
        Args:
            callObj: dictionary object contains phone call message.
        """
        call = {'cmd': callObj['callObject']['cmd'][0:3], 
                'number': callObj['callObject']['cmd'][3:-1]}
        self.calllist.append(call)
    
    def __parseSms(self, smsObj):
        """Parse dial message form parameter and store it into smslist of the member variable.
        
        Args:
            smsObj: dictionary object contains sms message.
        """
        phoneLen = int(smsObj['smsObject']['sms'][6:8], 16)
        if phoneLen % 2 != 0:
            phoneLen += 1
        phoneNumCode = smsObj['smsObject']['sms'][10:phoneLen+10]
        phoneNum = self.decodePhoneNum(phoneNumCode)
        encoding = smsObj['smsObject']['sms'][phoneLen+10+2:phoneLen+10+2+2]
        msgCode = smsObj['smsObject']['sms'][phoneLen+10+4+2:]
        msg = ''
        if encoding == '00':
            msg = self.msg7bitDecode(msgCode)
        elif encoding == '08':
            msg = self.msgUCS2Decode(msgCode)
        sms = {'destnum': phoneNum, 'msg': msg}
        self.smslist.append(sms)
        
        
    def __parseFile(self, fileObj):
        """Parse dial message form parameter and store it filelist of the member variable.
        
        Args:
            fileObj: dictionary object contains file operation message.
        """
        fileAction = {'type': fileObj['pvcObject']['type'],
                      'path': fileObj['pvcObject']['path'],
                      'action': fileObj['pvcObject']['action']}
        self.filelist.append(fileAction)
        
    def __parseDial(self, dialObj):
        """Parse dial message form parameter and store it into diallist of the member variable.
        
        Args:
            dialObj: dictionary object contains dial message.
        """
        dial = {'cmd': dialObj['dialObject']['cmd']}
        self.diallist.append(dial)
    
    def __parseNet(self, netObj):
        """Parse net message form parameter and store it into netlist of the member variable.
        
        Args:
            netObj: dictionary object contains net message.
        """
        net = {'saddr': netObj['netObject']['saddr'],
               'daddr': netObj['netObject']['daddr'],
               'protocol': netObj['netObject']['protocol']}
        self.netlist.append(net)
        
    def decodePhoneNum(self, phoneNumCode):
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
    
    def msg7bitDecode(self, msgCode):
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
    
    def msgUCS2Decode(self, msgCode):
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
    
    def createXML(self):
        """Parse log file result, create xml and write the result to it.     
        
        Returns:
            An ElementTree object which is created depending on the message in function
            parameters' list.
        """
        content = """
        <content>    
        </content>
        """
        root = ET.fromstring(content)
        if len(self.smslist) > 0:
            smslists = ET.Element('smslists')
            root.append(smslists)
            for e in self.smslist:
                lists = ET.Element('list')
                ET.SubElement(lists, 'destnum').text = e['destnum']
                ET.SubElement(lists, 'msg').text = e['msg']
                smslists.append(lists)
        
        if len(self.diallist) > 0 or len(self.calllist) > 0:
            diallists = ET.Element('diallists')
            root.append(diallists)
            for e in self.calllist:
                call = ET.Element('call')
                ET.SubElement(call, 'number').text = e['number']
                ET.SubElement(call, 'cmd').text = e['cmd']
                diallists.append(call)
            for e in self.diallist:
                lists = ET.Element('list')
                ET.SubElement(lists, 'cmd').text = e['cmd']
                diallists.append(lists)

        if len(self.netlist) > 0:
            netlists = ET.Element('netlists')
            root.append(netlists)
            for e in self.netlist:
                lists = ET.Element('list')
                ET.SubElement(lists, 'saddr').text = e['saddr']
                ET.SubElement(lists, 'daddr').text = e['daddr']
                ET.SubElement(lists, 'protocol').text = e['protocol']
                netlists.append(lists)
        
        if len(self.filelist) > 0:
            filelists = ET.Element('filelists')
            root.append(filelists)
            for e in self.filelist:
                lists = ET.Element('list')
                ET.SubElement(lists, 'type').text = e['type']
                ET.SubElement(lists, 'path').text = e['path']
                ET.SubElement(lists, 'action').text = e['action']
                filelists.append(lists)
                
        self.__indent(root)
        return ET.ElementTree(root)
    
    def __indent(self, elem, level=0):
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
                self.__indent(elem, level+1)
            if not elem.tail or not elem.tail.strip():
                elem.tail = i
        else:
            if level and (not elem.tail or not elem.tail.strip()):
                elem.tail = i
    
    def loadLogFile(self, path):
        """load and parse log file.
        
        Args:
            path: log file path.
        """
        logf = open(path)
        for line in logf:
            npos = line.find('{')
            if npos >= 0:
                try:
                    logObj = json.loads(line[npos:])
                    if 'callObject' in logObj:
                        self.__parseCall(logObj)
                    if 'smsObject' in logObj:
                        self.__parseSms(logObj)
                    if 'dialObject' in logObj:
                        self.__parseDial(logObj)
                    if 'pvcObject' in logObj:
                        self.__parseFile(logObj)
                    if 'netObject' in logObj:
                        self.__parseNet(logObj)
                except:
                    print('Exception!')
                    continue
