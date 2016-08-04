import paramiko
import time
import re
import os
import json
import logging
import shutil
import socket
import sys

TODO = """
    -Add Requirements file
    -Fix README.md
    -Fix File structure
1- Check if TFTP Server enabled by checking port 69 | Done
2- Add Logic to compare files and only save if different
3- Split into more defs | DONE
4- Create a class | DONE
5- Add more Logging instances | Neverending :)
5- Add startup config backup | Done
6- Create another class for each Loop instance on def loop_data() | Done
7- Load credentials file | DONE
8- Send email for each backup
9- Add a Log that checks for the last time file was backed up, to be sent in every email
10- In exec_command() add a param that checks for the type of config to be backed up | Done
11- What if the device is not available? | Done (handled by Paramiko exceptions
12- Remember to enable DEBUG LOGGING
13- Add Paramiko Exceptions
14- Add a def to get local IP address | Done
15- Add more parameters to the config file like IP address, and only check if parameter doesn't exist
16- Create a CMD API
17- Replace Class instantiation when API available
18- Change the Try and Timeout Logic after the command is sent
19- Add an stdout debugger
20- Change the file_change_flag logic, only check if there's a difference in the Json file and apply it
21- Create a class for device features: name, ip, backups, credentials, version, etc..."""

# Logging configuration
log_file = 'logs.log'
log2stdout = True

if log2stdout:
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s %(message)s', stream=sys.stdout)
else:
    logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s %(message)s')

logging.info('+' * 80)
logging.info('Script Starting')


class ConfigBackup(object):
    def __init__(self):
        self.config_file = "config.json"
        self.tftp_location = "C:\TFTP-Root"
        self.file_path = "config.json"
        self.cred_path = "credentials"
        self.devices = "Devices"
        self.exec_date = time.strftime("%Y%m%d-%H%M%S")
        self.file_change_flag = 0
        self.check_times_flag = 1
        self.port = 69
        self.username = ''
        self.password = ''
        self.server_ip = ''

        self.data = {}

    def load_creds(self):
        """
        Assumes credentials file inside the config_folder
        Assumes credentials in format username + [space] + password
        :return:
        """

        try:
            with open(self.cred_path) as f:
                self.username, self.password = f.read().split()
                logging.debug("Credentials File Loaded")
            return True
        except EnvironmentError:
            logging.warning('Missing credential file')
            print 'missing cred file'
            return False
        except:
            logging.warning('Error while loading the credentials file')
            print 'error while loadind cred file'
            return False

    def main(self):
        """
        Loads credentials
        Check if JSON config file exists, then load it in data dict
        Check if self.port in use, then continue or close and report
        Get Local server IP address
        :return: None
        """

        try:
            self.get_ip_address()
        except:
            logging.warning("Issues getting local IP")
            print "Issues getting local IP"

        if self.load_creds() and self.check_file(self.file_path) and self.server_ip:
            # Must split these items to better understand issues, separate them in defs to log there
            # then have them all in an if statement that execute code if all True
            self.file2json()
            logging.debug("Data File Loaded")

            if self.check_port_in_use():
                self.loop_data()
                self.check_changes()
            else:
                logging.info("Port {} open or having issues. Check TFTP Server".format(self.port))
        else:
            logging.info('Data File unavailable')

    def check_file(self, name):
        # Add a Log here to display of loaded or not, then remove the else on main
        return os.path.exists(name)

    def file2json(self):
        with open(self.file_path) as data_file:
            self.data = json.load(data_file)

    def json2file(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.data, f, sort_keys=True, indent=4, separators=(',', ': '))

    def exec_command(self, ip, file_name, config_type, src_file_path):
        """
        This Function executes a Paramiko instance with the defined IP, config type to be downloaded
        and the download file destination path
        It connects to the device, sends the command and checks file path every sec for 10 sec,
        until file shows, then closes connection
        if file not available, Log
        :param ip: IP of the device to be SSH'd
        :param file_name: name of the file to be passed to the SSH command
        :param config_type: Config file type: running or startup
        :param src_file_path: Path for the downloaded file
        :return: None
        """

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logging.info("Connecting to {} to download {} to {}".format(ip, file_name, src_file_path))

        try:
            ssh.connect(ip, username=self.username, password=self.password)
        except:
            logging.warning("Check Paramiko Logs")

        shell = ssh.invoke_shell()
        shell.send('\n\ncopy {}-config tftp {} {}\n'.format(config_type, self.server_ip, file_name))

        check_timeout = 10
        check_time_sec = 1

        while check_timeout > 0:
            logging.debug("Checking if file has been downloaded - {}".format(11 - check_timeout))

            if self.check_file(src_file_path):
                logging.debug("File downloaded from {}".format(ip))
                break
            else:
                check_timeout -= check_time_sec
                time.sleep(check_time_sec)
                while shell.recv_ready():
                    screen_log = self.cleanup(shell.recv(1024))
                    if screen_log:
                        logging.debug(screen_log)

        ssh.close()
        return

    def loop_data(self):
        """
        Read each device, execute command, generate a name, generate date
        :return:
        """

        for device_name, device_data in self.data.items():
            logging.info("looping on {}".format(device_name))

            self.each_file(device_name, device_data, 'running')
            self.each_file(device_name, device_data, 'startup')

    def each_file(self, device_name, device_data, config_type):

        file_name = "{}.{}.{}".format(device_name, self.exec_date, config_type)
        src_file_path = "{}\\{}".format(self.tftp_location, file_name)

        logging.info("Trying to backup file {}".format(file_name))
        self.exec_command(device_data['IP'], file_name, config_type, src_file_path)

        if self.check_file(src_file_path):
            logging.info("File {} has been created".format(file_name))

            # Update JSON file to reflect last date per config type
            self.data[device_name]['backups']["{}_last".format(config_type)] = self.exec_date
            # Add Logic to compare files

            # Move file from Download folder to Main folder
            self.file_mover(device_name, src_file_path)
            self.file_change_flag = 1
        else:
            logging.warning("File {} was not created".format(file_name))
            print "File {} was not created".format(file_name)

    def file_mover(self, device_name, src_file_path):
        """
        1- check if folder exists
        2- if not, create
        3- Copy file from TFTP root to folder
        4- Remove source file once copied
        """
        dst_folder_path = self.devices + '\\' + device_name
        dst_file_path = dst_folder_path + '\\' + src_file_path.split('\\')[-1]

        # Create Device folder if not exist
        if not self.check_file(self.devices):
            logging.debug("Device folder does't exist")
            os.makedirs(self.devices)

        # Create each device's folder if not exist
        if not self.check_file(dst_folder_path):
            logging.debug("Folder {} does't exist".format(device_name))
            os.makedirs(dst_folder_path)

        try:
            time.sleep(0.5)
            shutil.copy2(src_file_path, dst_file_path)
            time.sleep(0.5)
            os.remove(src_file_path)
        except:
            logging.warning("File {} couldn't move to {}".format(src_file_path, dst_file_path))
            print "File {} couldn't move to {}".format(src_file_path, dst_file_path)

        logging.info("File {} copied to Main folder".format(src_file_path.split('\\')[-1]))

    def check_changes(self):
        """
        If at least one change in self.data, then recreate JSON file
        """
        if self.file_change_flag:
            self.json2file()
        logging.info("JSON file changed")

    def check_port_in_use(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', self.port))
        if result:
            logging.info("Port {} in use, hopefully by the TFTP Server ;)".format(self.port))
        else:
            logging.warning("Turn the TFTP Server on!!!")
        return result

    def cleanup(self, message):
        procurve_re1 = re.compile(r'(\[\d+[HKJ])|(\[\?\d+[hl])|(\[\d+)|(\;\d+\w?)')
        procurve_re2 = re.compile(r'([E]\b)')
        procurve_re3 = re.compile(ur'[\u001B]+')
        message = procurve_re1.sub("", message)
        message = procurve_re2.sub("", message)
        message = procurve_re3.sub("", message)
        return message

    def get_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("www.google.com", 80))
        self.server_ip = s.getsockname()[0]
        logging.info("Server IP: {}".format(self.server_ip))
        s.close()

a = ConfigBackup()
a.main()
