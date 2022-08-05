# Project: palobackup
# Author: Jim Betts
# Date Written: July 28th, 2022
#
# This code is not supported in any manner. It is an unpublished proprietary work containing trade secrets
# that are the property of the author. All rights are reserved.
# No warranties exist for this script. This script is not guaranteed to perform any particular function
# and may cause damage, data loss, financial loss, or other harm to systems or persons when executed.
#
# Use of this script may be detrimental to your career, professional reputation, or personal life.
#
# Purpose: This module pulls a copy of the Palo Alto firewall device state and copies it to an SCP server
# This module connects to a Palo Alto Panorama management appliance and performs the following operations
# 1. Requests a list of connected firewalls
# 2. Generates a device state file on each firewall
# 3. Downloads the device state file to an SCP server
#
# Notes:
# * A file named "palobackup.xml" must exist in the working directory before execution
# * the "palobackup.xml" is in the following format:
# <Configuration>
#        <User>admin</User>
#        <Password encrypted="true">40486a3642707145793770372a444677</Password>
#        <SCPPath>backupuser@10.5.4.3:c:/fw-configs/</SCPPath>
# </Configuration>
# When a new password needs to be used, the 'encrypted="true"' attribute should either be removed or set to
# a value other than "true" as shown in the following example:
#        <Password encrypted="nope">secret-password99234</Password>
# When this is the case, the script will encrypt the password and re-write the
# configuration file. Note that the encryption used is very weak and simple. This file should be protected by
# access control mechanisms so that it can not be examined by unauthorized users.
#
# Alternatively, the username and password can be specified on the command line in this manner:
#   python palobackup.py user=simple password=complex2342
#
# Return values: the script will return a 0 if no errors were detected and a non-zero value if errors were detected.
#
# Install dependencies: paramiko, netmiko. Install at the CLI with: pip install paramiko netmiko
import time
import sys
import requests
import xml.etree.ElementTree as ElemTree
import datetime
import warnings
import netmiko

panoramaHostName = "168.32.73.55"
panoramaServer: str
username: str
password: str
sec_password: str
sec_copy_path: str
date_stamp: str


class BackupDevices(object):
    key: str
    devices: []
    netmiko_connect = None

    def __init__(self, user, pass_word, scp_path, scp_password):
        global username
        global password
        global sec_copy_path
        global sec_password
        username = user
        password = pass_word
        sec_copy_path = scp_path
        sec_password = scp_password

    @staticmethod
    def check_status(root) -> bool:
        response = root.find(".")
        if response is None:
            Exception("no response found")
        if not ("status" in response.attrib):
            Exception("status element not found")
        if response.get("status") != "success":
            Exception("request failed")
        return True

    def authenticate(self) -> bool:
        global username
        global password
        url = panoramaServer + "/api/?type=keygen&user=" + username + "&password=" + password
        response = requests.get(url, verify=False)
        root = ElemTree.fromstring(response.text)
        if not self.check_status(root):
            return False
        element = root.find("result/key")
        if element is None:
            Exception("key not present in authentication response")
        self.key = element.text
        return True

    def get_devices(self) -> bool:
        url = panoramaServer + "/api/?key=" + \
              self.key + "&type=op&cmd=<show><devices><connected></connected></devices></show>"
        response = requests.get(url, verify=False)
        root = ElemTree.fromstring(response.text)
        if not self.check_status(root):
            Exception("Unable to get_devices:" + response.text)
        self.devices = []
        for serial in root.findall(".//serial"):
            # avoid duplicates
            if not (serial in self.devices):
                self.devices.append(serial.text)
        return True

    @staticmethod
    def send_command(remote_conn, cmd, wait=1) -> str:
        while remote_conn.recv_ready():
            remote_conn.recv(4096)
        remote_conn.send(cmd)
        time.sleep(wait)
        buffer = None
        if remote_conn.recv_ready():
            buffer = remote_conn.recv(4096)
        return buffer

    def get_device_state(self, target_sn) -> bool:
        # this request generates the device state file
        url = panoramaServer + "/api/?type=export&category=device-state&key=" + self.key + "&target=" + target_sn
        response = requests.get(url, verify=False)
        root = ElemTree.fromstring(response.text)
        if not self.check_status(root):
            print("Unable to get_device_state on:" + target_sn + " - " + response.text)
            return False

        global username
        global password
        global sec_copy_path
        global sec_password
        global date_stamp

        if self.netmiko_connect is None:
            pano_key = {
                "device_type": "paloalto_panos",
                "host": panoramaHostName,
                "username": username,
                "password": password
            }
            self.netmiko_connect = netmiko.ConnectHandler(**pano_key)

        cmd = "scp export device-state device " + target_sn + " to " + sec_copy_path + "DS-" + target_sn + "-" +\
              date_stamp
        output = self.netmiko_connect.send_command_timing(cmd, strip_prompt=False, strip_command=False)
        if "The authenticity of host" in output:
            output = self.netmiko_connect.send_command_timing("yes", strip_prompt=False, strip_command=False)
        if "password:" in output:
            output = self.netmiko_connect.send_command_timing(sec_password, strip_prompt=False, strip_command=False)

        return True

    def get_device_config(self, target_sn) -> bool:
        url = panoramaServer + "/api/?type=config&action=show&key=" + self.key + \
              "&xpath=/config/devices/entry/vsys/entry/rulebase/security&target=" + target_sn
        response = requests.get(url, verify=False)
        root = ElemTree.fromstring(response.text)
        if not self.check_status(root):
            Exception("Unable to get_device_state on:" + target_sn + " - " + response.text)
        return True


class GetConfiguration(object):
    username: str
    password: str
    scp_path: str
    scp_password: str
    configfile = "palobackup.xml"

    def load(self) -> bool:
        tree = ElemTree.parse("palobackup.xml")
        self.username = ""
        self.password = ""
        self.scp_path = ""
        self.scp_password = ""
        # get the Panorama username
        element = tree.find("User")
        if element is None:
            print("Configuration/User not found")
        else:
            self.username = element.text
        # get the SCP target
        element = tree.find("SCPPath")
        if element is None:
            print("Configuration/SCPPath not found")
            return False
        self.scp_path = element.text
        # get the SCP password
        element = tree.find("SCPPassword")
        if element is None:
            print("Configuration/SCPPassword not found")
            return False
        self.scp_password = element.text
        # get the Panorama password
        element = tree.find("Password")
        if not (element is None):
            # See if the password needs to be encrypted. If the password is already encrypted, the
            # Password element will have an attribute that reads "encrypted=true"
            to_crypt = False
            if len(element.items()) == 0:
                to_crypt = True
            else:
                if not ("encrypted" in element.attrib):
                    to_crypt = True
                else:
                    if element.get("encrypted") != 'true':
                        to_crypt = True
            if to_crypt:
                print("Configuration file will be re-written with encrypted password")
                self.password = element.text
                element.set("encrypted", "true")
                crypt_bytes = element.text.encode("utf-8")
                element.text = crypt_bytes.hex()
                tree.write(self.configfile)
                return True

            self.password = bytes.fromhex(element.text).decode("utf-8")

        if len(sys.argv) > 2:
            for x in sys.argv:
                if(x[:5]) == "user=":
                    self.username = x[5:]
                else:
                    if (x[:9]) == "password=":
                        self.password = x[9:]

        if self.username == "":
            print("No user specified in config or CLI")
            return False
        if self.password == "":
            print("No password specified in config or CLI")
            return False
        if self.scp_path == "":
            print("No SCPPath specified in config file")
            return False
        if self.scp_password == "":
            print("No SCPPassword specified in config file")
            return False

        return True


if __name__ == '__main__':
    # ignore certificate warnings
    warnings.filterwarnings(action='ignore', module='.*paramiko.*')
    warnings.filterwarnings(action='ignore', module='.*urllib3.*')
    Conf = GetConfiguration()
    if not Conf.load():
        print("Error loading configuration")
        exit(1)
    d = datetime.date.today()
    date_stamp = d.strftime("%y-%m-%d")
    panoramaServer = "https://" + panoramaHostName
    BD = BackupDevices(user=Conf.username, pass_word=Conf.password, scp_path=Conf.scp_path,
                       scp_password=Conf.scp_password)
    failure_detected = False
    if not BD.authenticate():
        print("authentication failed")
        exit(1)
    if not BD.get_devices():
        print("get_devices failed")
        exit(1)
    for device in BD.devices:
        print(device)
        if not BD.get_device_state(device):
            print("get_device_state for " + device + " failed")
            failure_detected = True
        if not BD.get_device_config(device):
            print("get_device_config for " + device + " failed")
            failure_detected = True

    if failure_detected:
        print("Failures detected")
        exit(1)

    print("Backup completed with no errors")
    exit(0)
