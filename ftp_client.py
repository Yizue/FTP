# FTP Client - author: Steve Hirabayashi
from socket import *
import os
import os.path
import errno
import traceback
import sys
import argparse
import configparser

# Global constants
# Command List
CMD_H = "?"
CMD_HELP = "HELP"
CMD_QUIT = "QUIT"
CMD_CLOSE = "CLOSE"
CMD_BYE = "BYE"
CMD_DISCONNECT = "DISCONNECT"
CMD_LOGOUT = "LOGOUT"
CMD_LOGIN = "LOGIN"
CMD_OPEN = "OPEN"
CMD_USER = "USER"
CMD_PWD = "PWD"
CMD_PORT = "PORT"
CMD_PASSIVE = "PASSIVE"
CMD_ACTIVE = "ACTIVE"
CMD_LS = "LS"
CMD_CD = "CD"
CMD_CDUP = "CDUP"
CMD_MKDIR = "MKDIR"
CMD_RMDIR = "RMDIR"
CMD_DEL = "DEL"
CMD_DELETE = "DELETE"
CMD_RM = "RM"
CMD_RENAME = "RENAME"
CMD_TYPE = "TYPE"
CMD_ASCII = "ASCII"
CMD_BINARY = "BINARY"
CMD_IMAGE = "IMAGE"
CMD_TEXT = "TEXT"
CMD_GET = "GET"
CMD_PUT = "PUT"
CMD_APPEND = "APPEND"
CMD_LLS = "LLS"
CMD_LCD = "LCD"
CMD_NOOP = "NOOP"

# Global configuration variables
username = ""
password = ""
hostname = ""
ftp_port = None
data_port_min = None
data_port_max = None
testfile = ""
test_flag = None
logfile = ""
all_flag = None
configfile = 'client.cfg'
configs = None
next_data_port = 1
passive_flag = None
binary_flag = None
recv_buffer = None


def configure():
    global username, password, hostname, configfile, logfile, all_flag, ftp_port, data_port_min, data_port_max
    global testfile, test_flag, passive_flag, binary_flag, configs, recv_buffer

    # Parse program arguments
    parser = argparse.ArgumentParser()
    # Allow for I/O redirection of stdin
    parser.add_argument('infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin)

    parser.add_argument('-host', action="store", dest='host')
    parser.add_argument('-u', action="store", dest='user')
    parser.add_argument('-w', action="store", dest='pwrd')
    parser.add_argument('-fp', action="store", dest='fp', type=int)
    parser.add_argument('-dpr', action="store", dest='dpr')
    parser.add_argument('-c', action="store", dest='conf')

    group_mode = parser.add_mutually_exclusive_group()
    group_mode.add_argument('-P', action="store_true", default=False)
    group_mode.add_argument('-A', action="store_true", default=False)

    group_test = parser.add_mutually_exclusive_group()
    group_test.add_argument('-t', action="store", dest='test')
    group_test.add_argument('-T', action="store_true", default=False)

    parser.add_argument('-L', action="store", dest='logf')
    group_log = parser.add_mutually_exclusive_group()
    group_log.add_argument('-ALL', action="store_true", default=False)
    group_log.add_argument('-ONLY', action="store_true", default=False)

    parser.add_argument('-v', action="store_true", default=False)
    parser.add_argument('-info', action="store_true", default=False)

    args = parser.parse_args()

    # Determine if I/O redirection has occurred for stdin, read the program arguments
    if args.infile is not None and not sys.stdin.isatty():
        # Reads the first line that is not a comment
        prog_args = ['#']
        while prog_args[0] == '#':
            prog_args = sys.stdin.readline().split()

        for n in range(0, len(prog_args)):
            if prog_args[n] == '-host':
                args.host = prog_args[n + 1]
            if prog_args[n] == '-u':
                args.user = prog_args[n + 1]
            if prog_args[n] == '-w':
                args.pwrd = prog_args[n + 1]
            if prog_args[n] == '-fp':
                args.fp = prog_args[n + 1]
            if prog_args[n] == '-dpr':
                args.dpr = prog_args[n + 1]
            if prog_args[n] == '-c':
                args.conf = prog_args[n + 1]
            if prog_args[n] == '-P':
                args.P = True
            if prog_args[n] == '-A':
                args.A = True
            if prog_args[n] == '-T':
                args.T = True
            if prog_args[n] == '-t':
                args.test = prog_args[n + 1]
            if prog_args[n] == '-L':
                args.logf = prog_args[n + 1]
            if prog_args[n] == '-ALL':
                args.ALL = True
            if prog_args[n] == '-ONLY':
                args.ONLY = True
            if prog_args[n] == '-v':
                args.v = True
            if prog_args[n] == '-info':
                args.info = True

    # Retrieve default settings from configuration file, store into configs dict
    if args.conf is not None:
        configfile = get_pathname(args.conf)
    else:
        configfile = get_pathname(configfile)
    if not os.path.exists(configfile):
        print("Error: Could not find config file. Exiting...")
        sys.exit(1)
    configs = configparser.ConfigParser()
    configs.read(configfile)

    # Print Information as given by program arguments
    if args.v:
        print("FTP Client v" + configs['FTP_CLIENT']['FTP_VERSION'])
    if args.info:
        print("Author: Steve Hirabayashi\nPID: 2247504\nThis is a FTP Client that follows the RFC959 specifications\n" +
              "Use -h option to get usage for this program")

    # From config files and program arguments, set global variables
    if args.host is not None:
        hostname = args.host
    else:
        hostname = configs['FTP_CLIENT']['HOST_NAME']

    if args.user is not None:
        username = args.user
    if args.pwrd is not None:
        password = args.pwrd

    if args.fp is not None:
        ftp_port = args.fp
    else:
        ftp_port = int(configs['FTP_CLIENT']['DEFAULT_FTP_PORT'])

    if args.dpr is not None:
        data_port_range = (args.dpr.strip()).split('-')
        data_port_min = data_port_range[0]
        data_port_max = data_port_range[1]
    else:
        data_port_min = int(configs['FTP_CLIENT']['DATA_PORT_MIN'])
        data_port_max = int(configs['FTP_CLIENT']['DATA_PORT_MAX'])

    if args.test is not None:
        testfile = get_pathname(args.test)
        test_flag = True
        if not os.path.exists(testfile):
            print("Error: -t test file not found")
            sys.exit(1)
    elif args.T:
        testfile = get_pathname(configs['FTP_CLIENT']['PATH_TEST'])
        test_flag = True

    else:
        testfile = get_pathname(configs['FTP_CLIENT']['PATH_TEST'])
        test_flag = False

    if args.logf is not None:
        logfile = get_pathname(args.logf)
    else:
        logfile = get_pathname(configs['FTP_CLIENT']['PATH_LOG'])
    if not os.path.exists(logfile):
        print("Error: log file not found. Exiting...")
        sys.exit(1)

    if args.ONLY:
        all_flag = False
    else:
        all_flag = True

    if args.P:
        passive_flag = True
    elif args.A:
        passive_flag = False
    elif configs['FTP_CLIENT']['DEFAULT_MODE'] == 'Active':
        passive_flag = False
    elif configs['FTP_CLIENT']['DEFAULT_MODE'] == 'Passive':
        passive_flag = True

    if configs['FTP_CLIENT']['DEFAULT_TYPE'] == 'Text':
        binary_flag = False
    elif configs['FTP_CLIENT']['DEFAULT_TYPE'] == 'Binary':
        binary_flag = True

    recv_buffer = int(configs['FTP_CLIENT']['RECV_BUFFER'])


# entry point main()
def main():
    # Configure the program based on program arguments and configuration file
    configure()

    # Determine if user is ready to log in
    logged_on = False
    logon_ready = False
    if username != '' and password != '':
        logon_ready = True

    # Open log file to begin writing
    f_log = open(logfile, 'wt')
    f_log.write('Beginning FTP Client Session\n\n')

    if all_flag:
        print("You will be connected to host:", hostname)
        print("Type '?' for more information")
        print("Commands are NOT case sensitive\n")
    # Establish Connection
    f_log.write('Attempting to connect to FTP Server host: ' + hostname + "\n")
    ftp_socket = ftp_connecthost()
    f_log.write('FTP Socket:\n' + str(ftp_socket) + "\n")
    ftp_recv = msg_str_decode(ftp_socket.recv(recv_buffer), True)
    f_log.write('\tServer Response:\n\t' + ftp_recv + "\n")
    if all_flag:
        print(ftp_recv)

    # Check if connection was accepted
    if ftp_recv[:3] != '220':
        ftp_socket.close()
        if all_flag:
            print('Ending FTP Client Session')
        f_log.write('\nEnding FTP Client Session\n')
        f_log.close()
        sys.exit(0)

    # this is the only time that login is called without relogin
    # otherwise, relogin must be called
    if logon_ready:
        logged_on, cmd_msg = login(ftp_socket)
        if all_flag:
            print(cmd_msg)

    # Run test file if test_flag set to true
    if test_flag:
        # Open test file to begin reading
        f_test = open(testfile, 'rt')
        f_log.write('Beginning Test Case: ' + testfile + '\n\n')
        
        cmd_lines = f_test.readlines()
        for line in cmd_lines:
            try:
                if line.strip() == '' or line[0] == '#':
                    continue
                # Write command input to log file
                f_log.write('Input: ' + line + '\n')
                tokens = line.split()
                cmd_msg, logged_on, ftp_socket = run_cmds(tokens, logged_on, ftp_socket)
                # Write command result to log file
                if cmd_msg[:3].isdigit():
                    cmd_msg_list = cmd_msg.split('\n')
                    f_log.write('\tServer Response:\n')
                    for msg in cmd_msg_list:
                        f_log.write('\t' + msg + '\n')
                else:
                    f_log.write('\tClient Response: ' + cmd_msg + '\n')
                # Unrecognized Command
                if cmd_msg == 'Unknown':
                    if all_flag:
                        print("Unknown Command Entered. Use ? command to see list of recognized commands.")
                    f_log.write("Unknown Command Entered. Use ? command to see list of recognized commands.\n")
                elif cmd_msg != "":
                    if all_flag:
                        print(cmd_msg)
                # QUIT
                if cmd_msg[:3] == '221':
                    break

            except OSError as e:
                # A socket error
                str_error = str(e)
                if all_flag:
                    print("Socket error:", str_error)
                f_log.write("Socket error: " + str_error + '\n')
                # this exits but it is better to recover
                if str_error.find("[Errno 32]") >= 0:
                    sys.exit(1)
        f_test.close()
    else:
        # Request for client commands
        keep_running = True
        while keep_running:
            try:
                rinput = input("FTP>")
                if rinput is None or rinput.strip() == '':
                    continue
                # Write command input to log file
                f_log.write('Input: ' + rinput + '\n')
                tokens = rinput.split()
                cmd_msg, logged_on, ftp_socket = run_cmds(tokens, logged_on, ftp_socket)
                # Write command result to log file
                if cmd_msg[:3].isdigit():
                    cmd_msg_list = cmd_msg.split('\n')
                    f_log.write('\tServer Response:\n')
                    for msg in cmd_msg_list:
                        f_log.write('\t' + msg + '\n')
                else:
                    f_log.write('\tClient Response: ' + cmd_msg + '\n')
                # Unrecognized Command
                if cmd_msg == 'Unknown':
                    if all_flag:
                        print("Unknown Command Entered. Use ? command to see list of recognized commands.")
                    f_log.write("Unknown Command Entered. Use ? command to see list of recognized commands.\n")
                elif cmd_msg != "":
                    if all_flag:
                        print(cmd_msg)
                # QUIT
                if cmd_msg[:3] == '221':
                    keep_running = False

            except OSError as e:
                # A socket error
                if all_flag:
                    print("Socket error:", e)
                f_log.write("Socket error: " + e + '\n')
                str_error = str(e)
                # this exits but it is better to recover
                if str_error.find("[Errno 32]") >= 0:
                    sys.exit(1)

    # Close socket
    try:
        ftp_socket.close()
        if all_flag:
            print("Thank you for using FTP")
    except OSError as e:
        if all_flag:
            print("Socket error:", e)

    # Close log file
    f_log.write('\nEnding FTP Client Session\n')
    f_log.close()

    sys.exit(0)


def run_cmds(tokens, logged_on, ftp_socket):
    global username, password, hostname, configs, passive_flag, binary_flag

    cmd = tokens[0].upper()

    if cmd == CMD_H:
        h_ftp()
        return "Successfully displayed <?>", logged_on, ftp_socket

    if cmd == CMD_HELP:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, CMD_HELP)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_QUIT or cmd == CMD_CLOSE or cmd == CMD_BYE or cmd == CMD_DISCONNECT or cmd == CMD_LOGOUT:
        cmd_msg = quit_ftp(ftp_socket)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_LOGIN or cmd == CMD_OPEN or cmd == CMD_USER:
        logged_on, ftp_socket, cmd_msg = relogin(tokens, ftp_socket)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_PWD:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, CMD_PWD)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_PASSIVE:
        passive_flag = True
        return "Set Data Connections to Passive Mode", logged_on, ftp_socket

    if cmd == CMD_ACTIVE:
        passive_flag = False
        return "Set Data Connections to Active Mode", logged_on, ftp_socket

    if cmd == CMD_LS:
        # FTP must create a channel to received data before executing ls.
        # Also makes sure that data_socket is not None (exists)
        if passive_flag:
            cmd_msg, data_socket = ftp_new_dataport_passive(ftp_socket)
        else:
            cmd_msg, data_socket = ftp_new_dataport_active(ftp_socket)
        if data_socket is not None:
            cmd_msg_2 = ls_ftp(tokens, ftp_socket, data_socket)
            return (cmd_msg + '\n' + cmd_msg_2), logged_on, ftp_socket
        else:
            return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_CD:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, "CWD")
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_CDUP:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, CMD_CDUP)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_MKDIR:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, "MKD")
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_RMDIR:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, "RMD")
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_DELETE or cmd == CMD_RM or cmd == CMD_DEL:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, "DELE")
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_RENAME:
        if len(tokens) != 3:
            return "Invalid parameter count for rename", logged_on, ftp_socket
        cmd_msg = send_basic_cmd(tokens[:2:], ftp_socket, "RNFR")
        if cmd_msg[:3] != '350':
            return cmd_msg, logged_on, ftp_socket
        cmd_msg_2 = send_basic_cmd(tokens[::2], ftp_socket, "RNTO")
        return (cmd_msg + '\n' + cmd_msg_2), logged_on, ftp_socket

    if cmd == CMD_TYPE:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, "TYPE")
        if cmd_msg[:3] == '200':
            if tokens[1] == 'A':
                binary_flag = False
            elif tokens[1] == 'I' or tokens[1] == 'L':
                binary_flag = True
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_ASCII or cmd == CMD_TEXT:
        ftp_socket.send(str_msg_encode("TYPE A\r\n"))
        cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_IMAGE or cmd == CMD_BINARY:
        ftp_socket.send(str_msg_encode("TYPE I\r\n"))
        cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
        return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_GET:
        # FTP must create a channel to received data before executing put.
        # Also makes sure that data_socket is not None (exists)
        if passive_flag:
            cmd_msg, data_socket = ftp_new_dataport_passive(ftp_socket)
        else:
            cmd_msg, data_socket = ftp_new_dataport_active(ftp_socket)
        if data_socket is not None:
            cmd_msg_2 = get_ftp(tokens, ftp_socket, data_socket)
            return (cmd_msg + '\n' + cmd_msg_2), logged_on, ftp_socket
        else:
            return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_PUT:
        # FTP must create a channel to received data before executing put.
        # Also makes sure that data_socket is not None (exists)
        if passive_flag:
            cmd_msg, data_socket = ftp_new_dataport_passive(ftp_socket)
        else:
            cmd_msg, data_socket = ftp_new_dataport_active(ftp_socket)
        if data_socket is not None:
            cmd_msg_2 = put_ftp(tokens, ftp_socket, data_socket, False)
            return (cmd_msg + '\n' + cmd_msg_2), logged_on, ftp_socket
        else:
            return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_APPEND:
        if passive_flag:
            cmd_msg, data_socket = ftp_new_dataport_passive(ftp_socket)
        else:
            cmd_msg, data_socket = ftp_new_dataport_active(ftp_socket)
        if data_socket is not None:
            cmd_msg_2 = put_ftp(tokens, ftp_socket, data_socket, True)
            return (cmd_msg + '\n' + cmd_msg_2), logged_on, ftp_socket
        else:
            return cmd_msg, logged_on, ftp_socket

    if cmd == CMD_LLS:
        # Check if too many parameters or file does not exist
        if len(tokens) > 2:
            return "Too many parameters for LLS", logged_on, ftp_socket
        path = os.getcwd()
        if len(tokens) == 2:
            path = os.path.relpath(tokens[1])
            if not os.path.exists(path):
                return path + " not found", logged_on, ftp_socket

        if os.path.isfile(path):
            print(path)
        elif os.path.isdir(path):
            list_dir = os.listdir(path)
            for filename in list_dir:
                print(filename)
        return 'Successfully displayed "' + path + '"', logged_on, ftp_socket

    if cmd == CMD_LCD:
        # Check if too many parameters or file does not exist
        if len(tokens) > 2:
            return "Too many parameters for LCD", logged_on, ftp_socket
        if len(tokens) == 2:
            path = os.path.relpath(tokens[1])
            if not os.path.exists(path):
                return path + " not found", logged_on, ftp_socket
        else:
            return 'New directory: "' + os.getcwd() + '"', logged_on, ftp_socket

        if os.path.isfile(path):
            return path + " is not a directory", logged_on, ftp_socket
        elif os.path.isdir(path):
            os.chdir(path)
        return 'New directory: "' + os.getcwd() + '"', logged_on, ftp_socket

    if cmd == CMD_NOOP:
        cmd_msg = send_basic_cmd(tokens, ftp_socket, CMD_NOOP)
        return cmd_msg, logged_on, ftp_socket

    return "Unknown", logged_on, ftp_socket


def send_basic_cmd(tokens, ftp_socket, srv_cmd):
    msg = srv_cmd
    for token in tokens[1:]:
        msg = msg + " " + token
    msg += '\r\n'
    ftp_socket.send(str_msg_encode(msg))
    return msg_str_decode(ftp_socket.recv(recv_buffer), True)


def h_ftp():
    print("FTP Client Help")
    print("Commands are not case sensitive\n")
    print(CMD_H + "\t\t Prints help for FTP Client.")
    print(CMD_HELP + "\t\t Prints help for FTP Server Command. HELP [command_name]")
    print(CMD_LOGIN + "\t\t Login. It expects username and password. LOGIN [username] [password]. ALT: OPEN, USER")
    print(CMD_QUIT + "\t\t Exits ftp. ALT: CLOSE, BYE, DISCONNECT, LOGOUT")
    print(CMD_PASSIVE + "\t\t Set Data Connections to Passive Mode")
    print(CMD_ACTIVE + "\t\t Set Data Connections to Active Mode")
    print(CMD_PWD + "\t\t Prints current (remote) working directory.")
    print(CMD_LS + "\t\t Prints out remote directory content. LS [path_to_directory]. ALT: LCD")
    print(CMD_CD + "\t\t Changes current (remote) working directory. CD [path_to_directory]")
    print(CMD_CDUP + "\t\t Change to parent (remote) working directory.")
    print(CMD_MKDIR + "\t\t Creates empty directory. MKDIR [directory_name]")
    print(CMD_RMDIR + "\t\t Removes directory and its contents. RMDIR [directory_name]")
    print(CMD_DELETE + "\t\t Deletes remote file. DELETE [remote_file]. ALT: RM, DEL")
    print(CMD_RENAME + "\t\t Renames (and moves) remote file or directory. MV old_file_name new_file_name")
    print(CMD_TYPE + "\t\t Sets file transfer to either ASCII or Image. TYPE [A (Text)/I (Image)]")
    print(CMD_ASCII + "\t\t Sets file transfer to ASCII format. ALT: TEXT")
    print(CMD_IMAGE + "\t\t Sets file transfer to Image format. ALT: BINARY")
    print(CMD_GET + "\t\t Gets remote file. GET remote_file [name_in_local_system]")
    print(CMD_PUT + "\t\t Sends local file. PUT local_file [name_in_remote_system]")
    print(CMD_APPEND + "\t\t Appends local file. APPEND local_file [name_in_remote_system]")
    print(CMD_LLS + "\t\t Prints out local directory content. LLS [path_to_directory]")
    print(CMD_LCD + "\t\t Change to local directory. LCD [path_to_directory]")
    print(CMD_NOOP + "\t\t Not an operation, ping the server.")


def login(ftp_socket):
    global username, password, logfile
    if username is None or username.strip() == "":
        return False, "Username is blank. Try again"

    if all_flag:
        print("Attempting to login user:", username)
    with open(logfile, 'wt') as f_log:
        f_log.write("Attempting to login user: " + username + "\n")
    # Send command user
    ftp_socket.send(str_msg_encode("USER " + username + "\n"))
    cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)

    ftp_socket.send(str_msg_encode("PASS " + password + "\n"))
    cmd_msg_2 = msg_str_decode(ftp_socket.recv(recv_buffer), True)

    if cmd_msg[:3] != "331":
        return False, cmd_msg
    elif cmd_msg_2[:3] != "230":
        return False, cmd_msg_2
    else:
        return True, (cmd_msg + '\n' + cmd_msg_2)


def relogin(tokens, ftp_socket):
    global username, password
    if len(tokens) < 3:
        print("LOGIN requires more arguments. LOGIN [username] [password]")
        print("You will be prompted for username and password now")
        username = input("User:")
        password = input("Pass:")
    elif len(tokens) > 3:
        return False, ftp_socket, "Too Many Arguments. LOGIN [username] [password]"
    else:
        username = tokens[1]
        password = tokens[2]

    logged_on, cmd_msg = login(ftp_socket)
    return logged_on, ftp_socket, cmd_msg


def str_msg_encode(str_value):
    msg = str_value.encode()
    return msg


def msg_str_decode(msg, p_strip=False):
    # Print("msg_str_decode:" + str(msg))
    str_value = msg.decode()
    if p_strip:
        str_value.strip('\n')
    return str_value


def get_pathname(pathname, cwd=os.getcwd()):
    path = cwd
    pathname = pathname.replace('\\', '/')
    files = pathname.split('/')
    for dir in files:
        if dir is not None:
            path = os.path.join(path, dir)
    return os.path.normpath(path)


def ftp_connecthost():
    ftp_socket = socket(AF_INET, SOCK_STREAM)
    # To reuse socket faster. It has very little consequence for ftp client
    ftp_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    ftp_socket.connect((hostname, ftp_port))
    return ftp_socket


def quit_ftp(ftp_socket):
    if all_flag:
        print("Quitting...")
    cmd_msg = ""
    try:
        ftp_socket.send(str_msg_encode("QUIT\r\n"))
        cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
        if ftp_socket is not None:
            ftp_socket.close()
    except OSError:
        if all_flag:
            print("Socket was not able to be close. It may have been closed already")
    return cmd_msg


def ftp_new_dataport_passive(ftp_socket):
    ftp_socket.send(str_msg_encode("PASV\r\n"))
    cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
    if cmd_msg[:3] != '227':
        return cmd_msg, None

    data_sock_token = cmd_msg[5:].split(',')
    data_sock_addr = '.'.join(data_sock_token[:4])
    data_sock_port = int(data_sock_token[4]) * 256 + int(data_sock_token[5])
    return cmd_msg, (data_sock_addr, data_sock_port)


def ftp_new_dataport_active(ftp_socket):
    global next_data_port
    dport = next_data_port
    host = gethostname()
    host_address = gethostbyname(host)
    next_data_port += 1  # For next data port
    dport = (data_port_min + dport) % data_port_max
    # Create data socket
    if all_flag:
        print("Preparing Data Port: " + host + " " + host_address + " " + str(dport))
    data_socket = socket(AF_INET, SOCK_STREAM)
    # Reuse port
    data_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    data_socket.bind((host_address, dport))
    data_socket.listen(int(configs['FTP_CLIENT']['DATA_PORT_BACKLOG']))

    # The port requires the following
    # PORT IP PORT
    # However, it must be transmitted like this.
    # PORT 192,168,1,2,17,24
    # Where the first four octet are the ip and the last two form a port number.
    host_address_split = host_address.split('.')
    high_dport = str(dport // 256)
    low_dport = str(dport % 256)
    port_argument_list = host_address_split + [high_dport, low_dport]
    port_arguments = ','.join(port_argument_list)
    cmd_port_send = CMD_PORT + ' ' + port_arguments + '\r\n'
    if all_flag:
        print(cmd_port_send)

    try:
        ftp_socket.send(str_msg_encode(cmd_port_send))
    except socket.timeout:
        return "Socket timeout. Port may have been used recently. wait and try again!", None
    except OSError:
        return "Socket error. Try again", None
    cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
    return cmd_msg, data_socket


def ls_ftp(tokens, ftp_socket, data_socket):
    if len(tokens) > 1:
        ftp_socket.send(str_msg_encode("LIST " + tokens[1] + "\r\n"))
    else:
        ftp_socket.send(str_msg_encode("LIST\r\n"))

    if passive_flag:  # Passive Mode
        data_connection = socket(AF_INET, SOCK_STREAM)
        data_connection.connect(data_socket)

    # Message on connection of data socket
    cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
    if cmd_msg[:3] != '150':
        return cmd_msg

    if not passive_flag:  # Active Mode
        data_connection, data_host = data_socket.accept()

    # Ready to receive data
    msg = data_connection.recv(recv_buffer)
    while len(msg) > 0:
        msg_dec = msg_str_decode(msg, False).rstrip()
        print(msg_dec)
        msg = data_connection.recv(recv_buffer)

    # Close data connection socket
    data_connection.close()
    return cmd_msg + '\n' + msg_str_decode(ftp_socket.recv(recv_buffer), True)


def get_ftp(tokens, ftp_socket, data_socket):
    # Check if missing parameter
    if len(tokens) < 2:
        return "GET [filename]. Please specify filename"
    elif len(tokens) > 3:
        return "Too many parameters for GET"

    remote_filename = tokens[1]
    if len(tokens) == 3:
        filename = tokens[2]
    else:
        filename = remote_filename

    ftp_socket.send(str_msg_encode("RETR " + remote_filename + "\r\n"))
    if all_flag:
        print("Attempting to write file. Remote: " + remote_filename + " - Local: " + filename)

    if passive_flag:  # Passive Mode
        data_connection = socket(AF_INET, SOCK_STREAM)
        data_connection.connect(data_socket)

    cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
    if cmd_msg[:3] != "150":
        return cmd_msg

    if not passive_flag:  # Active Mode
        data_connection, data_host = data_socket.accept()

    # Ready to receive data
    # Begin receiving data and writing to file
    # Set mode to text or binary depending on type of file transferred
    mode = 'wt'
    if binary_flag:
        mode = 'wb'
    f_recv = open(filename, mode)

    size_recv = 0
    # Use write so it doesn't produce a new line (like print)
    if all_flag:
        sys.stdout.write("|")
    try:
        while True:
            if all_flag:
                sys.stdout.write("*")
            data = data_connection.recv(recv_buffer)
            if not binary_flag:
                data = data.decode('ascii')
            # Check if end of transmission
            if not data or data == '' or len(data) <= 0:
                f_recv.close()
                break
            else:
                f_recv.write(data)
                size_recv += len(data)
    except (OSError, UnicodeDecodeError):  # Invalid type specified
        f_recv.close()
        data_connection.close()
        # Remove the corrupted file
        os.remove(filename)
        return msg_str_decode(ftp_socket.recv(recv_buffer), True)

    if all_flag:
        sys.stdout.write("|")
        sys.stdout.write("\n")

    # Close data connection socket
    data_connection.close()
    return cmd_msg + '\n' + msg_str_decode(ftp_socket.recv(recv_buffer), True)


def put_ftp(tokens, ftp_socket, data_socket, append_flag):
    # Check if missing parameter
    if len(tokens) < 2:
        if append_flag:
            return "APPEND [local_file] [remote_file]. Please specify both files"
        else:
            return "PUT [filename]. Please specify filename"
    elif len(tokens) == 2 and append_flag:
        return "APPEND [local_file] [remote_file]. Please specify both files"
    elif len(tokens) > 3:
        if append_flag:
            return "Too many parameters for APPEND"
        else:
            return "Too many parameters for PUT"

    local_filename = tokens[1]
    if len(tokens) == 3:
        filename = tokens[2]
    else:
        filename = local_filename

    if not os.path.isfile(local_filename):
        return "Filename does not exist on this client. Filename: " + local_filename + " -- Check file name and path"

    filestat = os.stat(local_filename)
    filesize = filestat.st_size

    if passive_flag:  # Passive Mode
        data_connection = socket(AF_INET, SOCK_STREAM)
        data_connection.connect(data_socket)

    if append_flag:
        ftp_socket.send(str_msg_encode("APPE " + filename + "\r\n"))
    else:
        ftp_socket.send(str_msg_encode("STOR " + filename + "\r\n"))
    cmd_msg = msg_str_decode(ftp_socket.recv(recv_buffer), True)
    if cmd_msg[:3] != '150':
        return cmd_msg

    if not passive_flag:  # Active Mode
        data_connection, data_host = data_socket.accept()

    # Ready to send over file
    if all_flag:
        print("Attempting to send file. Local: " + local_filename + " - Remote: " + filename + " - Size:" + str(filesize))

    # Begin reading from file and sending data
    # Set mode to text or binary depending on type of file transferred
    mode = 'rt'
    if binary_flag:
        mode = 'rb'
    f_send = open(local_filename, mode)

    size_sent = 0
    # Use write so it doesn't produce a new line (like print)
    if all_flag:
        sys.stdout.write("|")
    try:
        while True:
            if all_flag:
                sys.stdout.write("*")
            data = f_send.read(recv_buffer)
            # Check if end of transmission
            if not data or data == '' or len(data) <= 0:
                f_send.close()
                break
            else:
                if binary_flag:
                    data_connection.send(data)
                else:
                    data_connection.send(data.encode('ascii'))
                size_sent += len(data)
    except (OSError, UnicodeDecodeError):  # Invalid type set
        f_send.close()
        data_connection.close()
        return msg_str_decode(ftp_socket.recv(recv_buffer), True)

    if all_flag:
        sys.stdout.write("|")
        sys.stdout.write("\n")

    # Close data connection socket
    data_connection.close()
    return msg_str_decode(ftp_socket.recv(recv_buffer), True)

if __name__ == "__main__":
    main()
