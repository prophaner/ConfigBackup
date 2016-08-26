import paramiko
import time
import re
import os
import json
import logging
import shutil
import socket
import difflib

# Logging configuration
log_file = 'logs.log'
logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s %(message)s')
log2stdout = True

if log2stdout:
    # logging.basicConfig(filename=log_file, level=logging.DEBUG, format='%(asctime)s %(message)s', stream=sys.stdout)
    logger = logging.getLogger('spam_application')
    logger.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)
    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(ch)

logging.info('+' * 80)
logging.info('Script Starting')


class ConfigBackup(object):
    def __init__(self):
        self.config_file = "config.json"
        self.tftp_location = "C:\TFTP-Root"
        self.file_path = "config.json"
        self.cred_path = "credentials"
        self.devices_folder = "Devices"
        self.exec_date = time.strftime("%Y%m%d-%H%M%S")

        self.server_details = ''
        self.server_ip = ''
        self.server_port = ''
        self.server_hostname = ''
        self.devices = {}
        self.file_change_flag = 0

        self.username = ''
        self.password = ''

        self.data = {}
        self.run_script = True

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

    def main(self):
        """
        -Load config file
        -Load IP address
        -Load Port
        -Check Port
        -Load Credentials
        -If all load fine, continue
        :return: None
        """

        if self.check_file(self.file_path):
            self.file2json()
            logging.debug("Data File Loaded")

        if not self.server_ip:
            try:
                grab_first_device_ip = self.devices[self.devices.keys()[0]]['ip']
                self.get_next_hop(grab_first_device_ip)
                self.data['server_details']['ip'] = self.server_ip
                self.file_change_flag = 1
            except:
                logging.warning("Issues getting local IP")
                return

        if not self.server_port:
            self.server_port = 69
            self.data['server_details']['port'] = self.server_port
            self.file_change_flag = 1

        if not self.check_port_in_use():
            return

        if not self.load_creds():
            return "Issues loading credentials"

        self.loop_data()

    def loop_data(self):
        """
        Read each device, execute command, generate a name, generate date
        :return:
        """

        for device_name, device_data in self.devices.items():
            logging.info("looping on {}".format(device_name))

            self.each_file(device_name, device_data, 'running')
            self.each_file(device_name, device_data, 'startup')

        self.check_changes()

    def each_file(self, device_name, device_data, config_type):
        file_name = "{}.{}.{}".format(device_name, self.exec_date, config_type)
        src_file_path = "{}\\{}".format(self.tftp_location, file_name)
        device_ip = device_data.get('ip')
        old_config_file = ''
        new_config_file = ''
        old_config_file_name = device_data.get('{}_backup'.format(config_type))
        add_file_flag = 0
        command_executed_flag = 0

        logging.info("Trying to backup file {}".format(file_name))
        if device_ip:
            try:
                self.exec_command(device_ip, file_name, config_type, src_file_path)
                command_executed_flag = 1
            except:
                logging.info("Command execution failed")
        else:
            logging.warning('Device {} missing IP address'.format(device_name))

        if command_executed_flag:
            # Load old file if exists
            if old_config_file_name:
                old_file_location = '\{}\{}\{}'.format(self.devices_folder, device_name, old_config_file_name)
                old_config_file = self.open_file(old_file_location)

            # Load new file if exists
            if self.check_file(src_file_path):
                logging.info("File {} has been created".format(file_name))
                new_config_file = self.open_file(src_file_path)
            else:
                logging.warning("File {} was not created".format(file_name))

            # Compare files, if no diff, then just delete new file. Else, cut new file, change Json and Log diff
            diff = '\n'.join(self.compare(old_config_file, new_config_file))
            diff_d = self.changes(diff)
            logging.info("Comparison between {} and {}".format(file_name, old_config_file_name))

            if diff_d['_'] > 0:
                if diff_d['+'] > 0 or diff_d['-'] > 0 or diff_d['?'] > 0:
                    # Adding changes to the INFO Log if changes
                    logging.debug(diff)
                    logging.info("Found changes")
                    add_file_flag += 1
                else:
                    logging.info("No changes found")
                    # Flag to break
            else:
                logging.info("Comparison is empty".format(file_name, old_config_file_name))
                # Flag to break

            # Mark last time script ran for every file
            self.data['devices'][device_name]['backups']['{}_last'.format(config_type)] = self.exec_date

            if add_file_flag:
                # Update JSON file to reflect file name for last time script ran
                self.data['devices'][device_name]['backups']['{}_name'.format(config_type)] = file_name

                # Move file from Download folder to Main folder
                self.file_mover(device_name, src_file_path)
                self.file_change_flag = 1
            else:
                os.remove(src_file_path)

    def compare(self, old_config_file, new_config_file):
        d = difflib.Differ()
        diff = d.compare(old_config_file.splitlines(), new_config_file.splitlines())
        return '\n'.join(diff)

    def check_file(self, name):
        # Add a Log here to display if loaded or not, then remove the else on main
        return os.path.exists(name)

    def file2json(self):
        try:
            with open(self.file_path) as data_file:
                self.data = json.load(data_file)
        except:
            logging.warning("JSON ERRORS")

        self.server_details = self.data.get('server_details')
        self.server_ip = self.server_details.get('ip')
        self.server_port = self.server_details.get('port')
        self.server_hostname = self.server_details.get('hostname')
        self.devices = self.data.get('devices')

    def open_file(self, path):
        with open(path) as f:
            return f.read()

    def json2file(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.data, f, sort_keys=True, indent=4, separators=(',', ': '))
            logging.debug("config file modified")

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

        # Time padding for each download
        time.sleep(1)
        return

    def file_mover(self, device_name, src_file_path):
        """
        1- check if folder exists
        2- if not, create
        3- Copy file from TFTP root to folder
        4- Remove source file once copied
        """
        dst_folder_path = self.devices_folder + '\\' + device_name
        dst_file_path = dst_folder_path + '\\' + src_file_path.split('\\')[-1]

        # Create Device folder if not exist
        if not self.check_file(self.devices_folder):
            logging.debug("Device folder does't exist")
            os.makedirs(self.devices_folder)

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
        result = sock.connect_ex(('127.0.0.1', self.server_port))
        if result:
            logging.info("Port {} in use, hopefully by the TFTP Server ;)".format(self.server_port))
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
        """Will only get local IP, ignores VPN"""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("www.google.com", 80))
        self.server_ip = s.getsockname()[0]
        logging.info("Server IP: {}".format(self.server_ip))
        s.close()

    def get_next_hop(self, dest_ip='4.2.2.2'):
        logging.info("Executing traceroute.")
        ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        try:
            raw_output = os.popen('tracert -d -h 1 -w 1 -4 {}'.format(dest_ip)).read()
            self.server_ip = re.findall(ipPattern, raw_output)[-1]
        except:
            logging.warning("Error doing a Traceroute")

    def changes(self, str):
        min_flag = 0
        plu_flag = 0
        que_flag = 0
        spaces = 0

        for i in str.splitlines():
            if i:
                if i[0] == '-':
                    min_flag += 1
                elif i[0] == '+':
                    plu_flag += 1
                elif i[0] == '?':
                    que_flag += 1
                else:
                    spaces += 1
            else:
                logging.info("Empty config")
        return {"-": min_flag, "+": plu_flag, "?": que_flag, "_": spaces}

a = ConfigBackup()
a.main()
