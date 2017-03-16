# FTP Server - author: Steve Hirabayashi
from socket import *
import threading
import sys
import os
import shutil
import argparse
import configparser

# Globals
thread_list = []
server_enable = None
ftp_service_port = None
ftp_server_port = None
data_port_min = None
data_port_max = None
mode = None
max_conns = None
max_retries = None
configfile = 'ftpserver\conf\server.cfg'
logfile = None
userfile = None

lock = threading.Lock()  # Lock for writing to logfile

configs = None
users = {}
root = ""
next_data_port = 1
recv_buffer = None
# Command List
CMD_HELP = "HELP"
CMD_QUIT = "QUIT"
CMD_USER = "USER"
CMD_PASS = "PASS"
CMD_PWD = "PWD"
CMD_PORT = "PORT"
CMD_PASV = "PASV"
CMD_LIST = "LIST"
CMD_CWD = "CWD"
CMD_CDUP = "CDUP"
CMD_MKD = "MKD"
CMD_RMD = "RMD"
CMD_DELE = "DELE"
CMD_RNFR = "RNFR"
CMD_RNTO = "RNTO"
CMD_TYPE = "TYPE"
CMD_RETR = "RETR"
CMD_STOR = "STOR"
CMD_APPE = "APPE"
CMD_NOOP = "NOOP"


def configure():
    global server_enable, ftp_service_port, ftp_server_port, data_port_min, data_port_max, mode, max_conns, max_retries
    global configfile, configs, userfile, users, logfile, root, recv_buffer

    # Parse program arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-port', action="store", dest='port', type=int)
    parser.add_argument('-dpr', action="store", dest='dpr')
    parser.add_argument('-config', action="store", dest='conf')
    parser.add_argument('-userdb', action="store", dest='user')
    parser.add_argument('-log', action="store", dest='log')
    parser.add_argument('-max', action="store", dest='max', type=int)
    parser.add_argument('-v', action="store_true", default=False)
    parser.add_argument('-info', action="store_true", default=False)
    args = parser.parse_args()

    if args.conf is not None:
        configfile = get_pathname(args.conf)
    else:
        configfile = get_pathname(configfile)
    # Retrieve default settings from configuration file, store into configs dict
    if not os.path.exists(configfile):
        print("Error: Could not find config file. Exiting...")
        sys.exit(1)
    configs = configparser.ConfigParser()
    configs.read(configfile)

    # Print Information as given by program arguments
    if args.v:
        print("FTP Server v" + configs['FTP_SERVER']['FTP_VERSION'])
    if args.info:
        print("Author: Steve Hirabayashi\nPID: 2247504\nThis is a FTP Server that follows the RFC959 specifications\n" +
              "Use -h option to get usage for this program")

    # From config files and program arguments, set global variables
    if configs['FTP_SERVER']['SERVER_ENABLE'] == "False":
        server_enable = False
    else:
        server_enable = True

    if args.port is not None:
        ftp_server_port = args.port
    else:
        ftp_server_port = int(configs['FTP_SERVER']['SERVER_PORT'])

    if args.dpr is not None:
        data_port_range = (args.dpr.strip()).split('-')
        data_port_min = data_port_range[0]
        data_port_max = data_port_range[1]
    else:
        data_port_min = int(configs['FTP_SERVER']['DATA_PORT_MIN'])
        data_port_max = int(configs['FTP_SERVER']['DATA_PORT_MAX'])

    if args.user is not None:
        userfile = get_pathname(args.user)
    else:
        userfile = get_pathname(configs['FTP_SERVER']['PATH_USER_FILE'])
    if args.log is not None:
        logfile = get_pathname(args.log)
    else:
        logfile = get_pathname(configs['FTP_SERVER']['PATH_LOG'])
    if not os.path.exists(logfile):
        print("Error: Could not find log file. Exiting...")
        sys.exit(1)

    if args.max is not None:
        max_conns = args.max
    else:
        max_conns = int(configs['FTP_SERVER']['MAX_CONNECTIONS'])

    max_retries = int(configs['FTP_SERVER']['RETRY_LIMIT'])
    ftp_service_port = int(configs['FTP_SERVER']['SERVICE_PORT'])
    recv_buffer = int(configs['FTP_SERVER']['RECV_BUFFER'])
        
    # Get user info from user database
    if not os.path.exists(userfile):
        print("Error: Could not find user file. Exiting...")
        sys.exit(1)
    with open(userfile, 'rt') as f_user:
        user_lines = f_user.readlines()
        for line in user_lines:
            if line[0] == "#" or line is None:
                continue
            else:
                user_tokens = line.split()
                # Username: password, acc_type, logged_in, login_try_count
                users[user_tokens[0]] = user_tokens[1], user_tokens[2], False, 0

    # Keep absolute path for root directory
    root = os.getcwd()


def main():
    global thread_list, server_enable
    # Configure the program based on program arguments and configuration file
    configure()

    # Setup service connection for server_run program
    service_socket = socket(AF_INET, SOCK_STREAM)
    service_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    service_socket.bind(('127.0.0.1', ftp_service_port))
    service_socket.listen(5)

    # Open log file to begin writing
    f_log = open(logfile, 'wt')
    f_log.write('Starting the FTP Server\n')

    # Create FTP Socket
    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server_socket.bind(('127.0.0.1', ftp_server_port))
    server_socket.listen(5)
    print('The FTP Server is ready')
    f_log.write('The FTP Server is ready\n')
    f_log.close()

    while True:
        if server_enable:  # Check if server is in suspended state
            # Receiving FTP connection from FTP Client
            server_socket.settimeout(1)  # Time out for socket
            try:
                connection_socket, addr = server_socket.accept()
                # Check if at the maximum connection limit
                if threading.active_count() < max_conns + 1:
                    # Send Confirmation Message
                    connection_socket.send(str_msg_encode('220 Service ready'))
                    write_server_response(addr, '220 Service ready')
                    print("*** Thread client entering now for: " + str(addr) + " ***")
                    print("Waiting for another connection")
                    with open(logfile, "at") as f_log:
                        f_log.write("*** Thread client entering now for: " + str(addr) + " ***" + '\n')
                    # Create and start thread for client
                    t = threading.Thread(target=client_thread, args=(connection_socket, addr))
                    t.start()
                    thread_list.append(t)
                else:
                    # Send Error message
                    connection_socket.send(str_msg_encode('421 Server is busy'))
                    write_server_response(addr, '421 Server is busy')
            except OSError:
                pass

        # Receiving suspend/resume/end connection from server_run
        service_socket.settimeout(1)  # Time out for socket
        try:
            srv_socket, addr = service_socket.accept()
            if srv_socket is not None:
                srv_msg = msg_str_decode(srv_socket.recv(recv_buffer))
                with open(logfile, "at") as f_log:
                    f_log.write("From: " + str(addr) + ": " + srv_msg + '\n')
                if srv_msg == "SUSPEND":
                    print('Server is now suspended')
                    with open(logfile, "at") as f_log:
                        f_log.write('Server is now suspended\n')
                    server_enable = False
                    srv_socket.send(str_msg_encode('OK'))
                    write_server_response(addr, 'OK')
                elif srv_msg == "RESUME":
                    print('Server is now restored')
                    with open(logfile, "at") as f_log:
                        f_log.write('Server is now restored\n')
                    server_enable = False
                    srv_socket.send(str_msg_encode('OK'))
                    write_server_response(addr, 'OK')
                elif srv_msg == "CLOSE":
                    srv_socket.send(str_msg_encode('OK'))
                    write_server_response(addr, 'OK')
                    break
                else:
                    srv_socket.send(str_msg_encode('ERR'))
                    write_server_response(addr, 'OK')
        except OSError:
            pass

    # Close both FTP control and service sockets
    service_socket.close()
    server_socket.close()
    for t in thread_list:
        t.join()
    # Close log file
    print("Closing the FTP Server")
    with open(logfile, "at") as f_log:
        f_log.write('Closing the FTP Server\n')
    sys.exit(0)


def client_thread(connection_socket, addr):
    cwd = get_pathname(configs['FTP_SERVER']['PATH_ROOT'])
    username = ""
    logged_in = False
    keep_running = True
    prev_cmd = ""
    data_socket_field = None
    pasv_flag = False
    if mode == 'Passive':
        pasv_flag = True
    rename = ""
    bin_flag = False
    if configs['FTP_SERVER']['DEFAULT_TYPE'] == 'Binary':
        bin_flag = True

    try:
        while keep_running:
            msg = connection_socket.recv(recv_buffer)
            tokens = msg_str_decode(msg).split()
            if len(tokens) == 0:
                break
            msg, keep_running, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag = \
                run_cmds(addr, tokens, connection_socket, prev_cmd, username, \
                    logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag)
            prev_cmd = tokens[0]
            write_server_response(addr, msg)
    except OSError as e:
        # A socket error
        lock.acquire()
        print("Socket error:", e)
        with open(logfile, "at") as f_log:
            f_log.write("Socket error: " + str(e))
        lock.release()

    lock.acquire()
    print("*** Thread closed for: " + str(addr) + " ***")
    with open(logfile, "at") as f_log:
        f_log.write("*** Thread closed for: " + str(addr) + " ***" + '\n')
    lock.release()


def run_cmds(addr, tokens, conn_socket, prev_cmd, username, logged_in, cwd, data_socket_field,
             pasv_flag, rename, bin_flag):
    print(tokens)
    with open(logfile, "at") as fin:
        fin.write("From " + str(addr) + ": " + str(tokens) + '\n')

    cmd = tokens[0].upper()

    if cmd == CMD_HELP:
        msg = help_ftp(tokens, conn_socket)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_QUIT:
        # Check if too many parameters
        msg, is_above = above_parameter_upper_limit(tokens, conn_socket, 1)
        if is_above:
            return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, bin_flag
        msg = '221 Server closing connection'
        conn_socket.send(str_msg_encode(msg))
        return msg, False, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_USER:
        msg, username, logged_in = \
            user_ftp(tokens, conn_socket, username, logged_in)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_PASS:
        msg, username, logged_in, cwd = \
            pass_ftp(tokens, conn_socket, prev_cmd, username, logged_in, cwd)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_PWD:
        # Check if logged in
        if not logged_in:
            msg = '550 Not logged in'
            conn_socket.send(str_msg_encode(msg))
            return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag
        # Check if too many parameters
        msg, is_above = above_parameter_upper_limit(tokens, conn_socket, 1)
        if is_above:
            return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

        rel_cwd = os.path.relpath(cwd)
        msg = '257 "' + rel_cwd + '\\"'
        conn_socket.send(str_msg_encode(msg))
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_PORT:
        msg, data_socket_field = port_ftp(tokens, conn_socket, logged_in, data_socket_field)
        return msg, True, username, logged_in, cwd, data_socket_field, False, rename, bin_flag

    if cmd == CMD_PASV:
        msg, data_socket_field = pasv_ftp(tokens, conn_socket, logged_in, data_socket_field)
        return msg, True, username, logged_in, cwd, data_socket_field, True, rename, bin_flag

    if cmd == CMD_LIST:
        msg, data_socket_field = list_ftp(tokens, conn_socket, logged_in, cwd, data_socket_field, pasv_flag)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_CWD:
        msg, cwd = cwd_ftp(tokens, conn_socket, username, logged_in, cwd)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_CDUP:
        msg, cwd = cdup_ftp(tokens, conn_socket, username, logged_in, cwd)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_MKD:
        msg = mkd_ftp(tokens, conn_socket, logged_in, cwd)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_RMD:
        msg = rmd_ftp(tokens, conn_socket, logged_in, cwd)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_DELE:
        msg = dele_ftp(tokens, conn_socket, logged_in, cwd)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_RNFR:
        msg, rename = rnfr_ftp(tokens, conn_socket, logged_in, cwd, rename)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_RNTO:
        msg, rename = rnto_ftp(tokens, conn_socket, prev_cmd, logged_in, cwd, rename)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_TYPE:
        msg, bin_flag = type_ftp(tokens, conn_socket, logged_in, bin_flag)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_RETR:
        msg, data_socket_field = retr_ftp(tokens, conn_socket, logged_in, cwd,
                                          data_socket_field, pasv_flag, bin_flag)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_STOR:
        msg, data_socket_field = stor_ftp(tokens, conn_socket, logged_in, cwd,
                                          data_socket_field, pasv_flag, bin_flag, False)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_APPE:
        msg, data_socket_field = stor_ftp(tokens, conn_socket, logged_in, cwd,
                                          data_socket_field, pasv_flag, bin_flag, True)
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    if cmd == CMD_NOOP:
        msg = '200 ' + CMD_NOOP + ' Command OK'
        conn_socket.send(str_msg_encode(msg))
        return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag

    # Unrecognized Command
    msg = '502 ' + cmd + ': Unrecognized Command'
    conn_socket.send(str_msg_encode(msg))
    return msg, True, username, logged_in, cwd, data_socket_field, pasv_flag, rename, bin_flag


def write_server_response(addr, response):
    lock.acquire()
    with open(logfile, "at") as fin:
        responses = response.split('\n')
        fin.write("\tTo " + str(addr) + ", send:\n")
        for resp in responses:
            fin.write('\t' + resp + '\n')
    lock.release()


def help_ftp(tokens, conn_socket):
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 1)
    if not correct_size:
        return msg
    cmd = tokens[1].upper()
    if cmd == CMD_HELP:
        msg = '214 Returns usage of command. ' + cmd + ' cmd_name'
    elif cmd == CMD_QUIT:
        msg = '214 Terminates Client. ' + cmd
    elif cmd == CMD_USER:
        msg = '214 Login user. ' + cmd + ' username'
    elif cmd == CMD_PASS:
        msg = '214 Login password. ' + cmd + ' password. MUST follow USER'
    elif cmd == CMD_PWD:
        msg = '214 Print current working directory. ' + cmd
    elif cmd == CMD_PORT:
        msg = '214 Send information to server to establish TCP data connection. ' + cmd + ' ip1,ip2,ip3,ip4,p1,p2'
    elif cmd == CMD_PASV:
        msg = '214 Send information to client to establish TCP data connection. ' + cmd
    elif cmd == CMD_LIST:
        msg = '214 Show list of files in current working directory. ' + cmd + ' [path]'
    elif cmd == CMD_CWD:
        msg = '214 Change current working directory. ' + cmd + ' path'
    elif cmd == CMD_CDUP:
        msg = '214 Change to parent working directory. ' + cmd
    elif cmd == CMD_MKD:
        msg = '214 Make directory. ' + cmd + ' path'
    elif cmd == CMD_RMD:
        msg = '214 Remove directory. ' + cmd + ' path'
    elif cmd == CMD_DELE:
        msg = '214 Delete a file. ' + cmd + ' path'
    elif cmd == CMD_RNFR:
        msg = '214 Mark file to be renamed. ' + cmd + ' path'
    elif cmd == CMD_RNTO:
        msg = '214 Rename file to new name. ' + cmd + ' path. MUST follow RNFR'
    elif cmd == CMD_TYPE:
        msg = '214 Set type of transmission to ASCII or Image. ' + cmd + ' A (ASCII)/I (IMAGE)'
    elif cmd == CMD_RETR:
        msg = '214 Retrieve file from server, send to client. ' + cmd + ' path'
    elif cmd == CMD_STOR:
        msg = '214 Store file from client to server. ' + cmd + ' path'
    elif cmd == CMD_APPE:
        msg = '214 Append file from client to server. ' + cmd + ' path'
    elif cmd == CMD_NOOP:
        msg = '214 Ping the server. ' + cmd
    else:
        msg = '502 ' + cmd + ': Unrecognized Command'
    conn_socket.send(str_msg_encode(msg))
    return msg


def user_ftp(tokens, conn_socket, username, logged_in):
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, '', logged_in
    # Check if already logged in
    if logged_in:
        msg = '202 ' + username + ' is already logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg,  username, logged_in
    # Check for existence of user in users dictionary
    if tokens[1] in users:
        pwrd, user_type, already_logged_in, try_count = users[tokens[1]]
        if already_logged_in:
            msg = '530 ' + tokens[1] + ' is already logged in'
            conn_socket.send(str_msg_encode(msg))
            return msg, tokens[1], logged_in
        elif user_type == 'User' or user_type == 'Admin':
            msg = '331 ' + tokens[1] + ' accepted, need password'
            conn_socket.send(str_msg_encode(msg))
            return msg, tokens[1], logged_in
        else:
            msg = '530 ' + tokens[1] + ' cannot login, status: ' + user_type
            conn_socket.send(str_msg_encode(msg))
            return msg, '', logged_in
    else:
        msg = '430 ' + tokens[1] + ' is not a valid username'
        conn_socket.send(str_msg_encode(msg))
        return msg, '', logged_in


def pass_ftp(tokens, conn_socket, prev_cmd, username, logged_in, cwd):
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, username, logged_in, cwd
    # Check if already logged in
    if logged_in:
        msg = '202 ' + username + ' is already logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, username, logged_in, cwd
    # Check if not before USER cmd
    if prev_cmd != 'USER':
        msg = '503 Bad Sequence of commands: PASS must come after USER'
        conn_socket.send(str_msg_encode(msg))
        return msg, username, logged_in, cwd
    # Check if not given username
    if username == '':
        msg = '530 Missing Username'
        conn_socket.send(str_msg_encode(msg))
        return msg, username, logged_in, cwd

    pwrd, user_type, already_logged_in, try_count = users[username]
    # Confirm if password given matches with users dictionary
    if tokens[1] == pwrd:
        msg = '230 Password ok, ' + username + ' logged in'
        conn_socket.send(str_msg_encode(msg))
        # Move the user to their specific userfile, create one if it doesnt exist
        user_dir = get_pathname(username, cwd)
        if not os.path.isdir(user_dir):
            os.mkdir(user_dir)
        return msg, username, True, user_dir
    else:
        # Update user profile, if number of tries reaches maximum limit, lock the account
        attempt_count = try_count + 1
        msg = '530 ' + tokens[1] + ': Wrong password'
        if attempt_count >= max_retries:
            msg += ". Max number of attempts made, user: " + username + " is now locked."
            users[username] = pwrd, "Locked", False, 0
            print(users[username])
            conn_socket.send(str_msg_encode(msg))
            return msg, username, False, cwd

        users[username] = pwrd, user_type, False, attempt_count
        print(users[username])
        conn_socket.send(str_msg_encode(msg))
        return msg, username, False, cwd


def port_ftp(tokens, conn_socket, logged_in, data_socket_field):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, None
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, None

    data_sock_token = tokens[1].split(',')
    data_sock_addr = '.'.join(data_sock_token[:4])
    data_sock_port = int(data_sock_token[4]) * 256 + int(data_sock_token[5])
    print(data_sock_addr, data_sock_port)
    # Check if data port is illegal
    if data_sock_port < data_port_min or data_sock_port > data_port_max:
        msg = '501 Illegal data port: ' + str(data_sock_port)
        conn_socket.send(str_msg_encode(msg))
        return msg, None

    msg = '200 PORT command OK'
    conn_socket.send(str_msg_encode(msg))
    return msg, (data_sock_addr, data_sock_port)


def pasv_ftp(tokens, conn_socket, logged_in, data_socket_field):
    global next_data_port
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 1)
    if not correct_size:
        return msg, data_socket_field

    d_port = next_data_port
    host = gethostname()
    host_address = gethostbyname(host)
    next_data_port += 1  # For next data port
    d_port = (data_port_min + d_port) % data_port_max
    # Create data socket
    print("Preparing Data Port: " + host + " " + host_address + " " + str(d_port))
    print("Preparing Data Port: " + host + " " + host_address + " " + str(d_port))
    data_socket = socket(AF_INET, SOCK_STREAM)
    # Reuse port
    data_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    data_socket.bind((host_address, d_port))
    data_socket.listen(int(configs['FTP_SERVER']['DATA_PORT_BACKLOG']))

    # The port requires the following
    # PORT IP PORT
    # However, it must be transmitted like this.
    # PORT 192,168,1,2,17,24
    # Where the first four octet are the ip and the last two form a port number.
    host_address_split = host_address.split('.')
    high_d_port = str(d_port // 256)
    low_d_port = str(d_port % 256)
    port_argument_list = host_address_split + [high_d_port, low_d_port]
    port_arguments = ','.join(port_argument_list)

    msg = '227 =' + port_arguments
    conn_socket.send(str_msg_encode(msg))
    return msg, data_socket


def list_ftp(tokens, conn_socket, logged_in, cwd, data_socket_field, pasv_flag):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Check if too many parameters
    msg, is_above = above_parameter_upper_limit(tokens, conn_socket, 2)
    if is_above:
        return msg, data_socket_field
    # Check if data connection exists
    if data_socket_field is None:
        msg = '425 No data socket'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Check if directory or file exists
    path = cwd
    is_dir = False
    is_file = False
    if len(tokens) > 1:
        path = get_pathname(tokens[1], cwd)
    if os.path.isdir(path):
        is_dir = True
    if os.path.isfile(path):
        is_file = True
    rel_path = os.path.relpath(path)
    if not (is_dir or is_file):
        msg = '550 "' + rel_path + '" does not exist'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field

    # Attempt to establish data connection
    try:
        if pasv_flag:  # Passive Mode
            data_socket, data_host = data_socket_field.accept()
        else:  # Active Mode
            data_socket = socket(AF_INET, SOCK_STREAM)
            data_socket.connect(data_socket_field)
    except OSError as e:
        # A socket error
        print("Socket error:", e)
        msg = '425 Error establishing data connection'
        conn_socket.send(str_msg_encode(msg))
        return msg, None
    msg = '150 Ready to send information for "' + rel_path + '"'
    conn_socket.send(str_msg_encode(msg))

    # Send over the list of files or filename
    if is_file:
        data_socket.send(str_msg_encode(rel_path))
    elif is_dir:
        list_dir = os.listdir(path)
        for filename in list_dir:
            data_socket.send(str_msg_encode(filename + '\n'))
    # Close data socket
    data_socket.close()
    msg_2 = '226 Information on "' + rel_path + '" successfully transmitted'
    conn_socket.send(str_msg_encode(msg_2))
    return (msg + '\n' + msg_2), None


def cwd_ftp(tokens, conn_socket, username, logged_in, cwd):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, cwd
    # Check if no parameter was sent
    rel_path = os.path.relpath(cwd)
    if len(tokens) == 1:
        msg = '250 Changed directory: "' + rel_path + '"'
        conn_socket.send(str_msg_encode(msg))
        return msg, cwd
    # Check if too many parameters were sent
    msg, is_above = above_parameter_upper_limit(tokens, conn_socket, 2)
    if is_above:
        return msg, cwd
    # Check special cases
    if tokens[1] == '.' or tokens[1] == './' or tokens[1] == '.\\':
        msg = '250 Changed directory: "' + rel_path + '"'
        conn_socket.send(str_msg_encode(msg))
        return msg, cwd
    if tokens[1] == '..' or tokens[1] == '../' or tokens[1] == '..\\':
        # Redirect to CDUP
        msg, cwd = cdup_ftp(tokens, conn_socket, username, logged_in, cwd)
        return msg, cwd
    # Check if directory exists
    path = get_pathname(tokens[1], cwd)
    rel_path = os.path.relpath(path)
    if os.path.isdir(path):
        msg = '250 Changed directory: "' + rel_path + '"'
        conn_socket.send(str_msg_encode(msg))
        return msg, path
    else:
        msg = '550 "' + rel_path + '" directory does not exist'
        conn_socket.send(str_msg_encode(msg))
        return msg, cwd


def cdup_ftp(tokens, conn_socket, username, logged_in, cwd):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, cwd
    # Check if too many parameters were sent
    msg, is_above = above_parameter_upper_limit(tokens, conn_socket, 1)
    if is_above:
        return msg, cwd

    head, tail = os.path.split(cwd)
    # Shave off extraneous element in list
    if tail is None:
        head, tail = os.path.split(head)

    # Check if at root folder (ftproot/ for administrators, username/ for users)
    pwrd, user_type, already_logged_in, retry_count = users[username]
    if user_type == "Admin":
        root = get_pathname(configs['FTP_SERVER']['PATH_ROOT'])
        root_head, root_tail = os.path.split(root)
        if root_tail is None:
            root_head, root_tail = os.path.split(root_head)
        if tail == root_tail:
            msg = '550 Access unavailable: at "' + root_tail + '/" - root folder'
            conn_socket.send(str_msg_encode(msg))
            return msg, cwd
    if user_type == "User" and tail == username:
        msg = '550 Access unavailable: at "' + username + '/" - root folder'
        conn_socket.send(str_msg_encode(msg))
        return msg, cwd

    # Jump to parent directory
    rel_new_dir = os.path.relpath(head)
    msg = '200 Changed Directory: "' + rel_new_dir + '"'
    conn_socket.send(str_msg_encode(msg))
    return msg, head


def mkd_ftp(tokens, conn_socket, logged_in, cwd):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg
    # Check if missing parameter or invalid filename
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg
    if '\\' in tokens[1] or '/' in tokens[1]:
        msg = '501 ' + tokens[1] + ': Invalid filename'
        conn_socket.send(str_msg_encode(msg))
        return msg
    # Check if file exists
    path = get_pathname(tokens[1], cwd)
    rel_path = os.path.relpath(path)

    try:
        os.mkdir(path)
    except FileExistsError:
        msg = '502 "' + rel_path + '" already exists'
        conn_socket.send(str_msg_encode(msg))
        return msg

    msg = '257 "' + rel_path + '" has been created'
    conn_socket.send(str_msg_encode(msg))
    return msg


def rmd_ftp(tokens, conn_socket, logged_in, cwd):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg

    path = get_pathname(tokens[1], cwd)
    rel_path = os.path.relpath(path)
    try:
        shutil.rmtree(path)
    except Exception:
        msg = '550 "' + rel_path + '" does not exist'
        conn_socket.send(str_msg_encode(msg))
        return msg

    msg = '250 "' + rel_path + '" has been successfully removed'
    conn_socket.send(str_msg_encode(msg))
    return msg


def dele_ftp(tokens, conn_socket, logged_in, cwd):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg

    rel_path = os.path.relpath(get_pathname(tokens[1], cwd))
    try:
        os.remove(rel_path)
    except OSError:
        msg = '550 ' + tokens[1] + ' does not exist'
        conn_socket.send(str_msg_encode(msg))
        return msg

    msg = '250 ' + tokens[1] + ' successfully removed'
    conn_socket.send(str_msg_encode(msg))
    return msg


def rnfr_ftp(tokens, conn_socket, logged_in, cwd, rename):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, rename
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, rename
    # Check if file exists
    rel_path = get_pathname(tokens[1], cwd)
    if not os.path.exists(rel_path):
        msg = '550 ' + tokens[1] + ' does not exist'
        conn_socket.send(str_msg_encode(msg))
        return msg, rename

    msg = '350 ' + tokens[1] + ' exists, send new name for file'
    conn_socket.send(str_msg_encode(msg))
    return msg, rel_path


def rnto_ftp(tokens, conn_socket, prev_cmd, logged_in, cwd, rename):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, rename
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, rename
    # Check if previous command is RNFR or not
    if prev_cmd != 'RNFR':
        msg = '503 Bad Sequence of commands: RNTO must follow RNFR'
        conn_socket.send(str_msg_encode(msg))
        return msg, ""

    old_name = os.path.relpath(rename)
    new_name = os.path.relpath(get_pathname(tokens[1], cwd))
    try:
        os.rename(old_name, new_name)
    except OSError:
        msg = '550 "' + old_name + '" could not be renamed to "' + new_name + '"'
        conn_socket.send(str_msg_encode(msg))
        return msg, ""

    msg = '250 "' + old_name + '" successfully renamed to "' + new_name + '"'
    conn_socket.send(str_msg_encode(msg))
    return msg, ""


def type_ftp(tokens, conn_socket, logged_in, bin_flag):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, bin_flag
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2, 3)
    if not correct_size:
        return msg, bin_flag
    # Check if parameters are valid
    if len(tokens) == 2:
        if tokens[1] == 'A':  # ASCII
            msg = '200 File Transfer set to Text'
            conn_socket.send(str_msg_encode(msg))
            return msg, False
        elif tokens[1] == 'I':  # Image
            msg = '200 File Transfer set to Image'
            conn_socket.send(str_msg_encode(msg))
            return msg, True
        else:
            msg = '501 Invalid parameter: ' + tokens[1]
            conn_socket.send(str_msg_encode(msg))
            return msg, bin_flag
    else:
        if tokens[1] == 'A' and tokens[2] == 'N':  # ASCII
            msg = '200 File Transfer set to Text'
            conn_socket.send(str_msg_encode(msg))
            return msg, False
        elif tokens[1] == 'L' and int(tokens[2]) == 8:  # Image
            msg = '200 File Transfer set to Image'
            conn_socket.send(str_msg_encode(msg))
            return msg, True
        else:
            msg = '501 Invalid parameters: ' + tokens[1] + ' ' + tokens[2]
            conn_socket.send(str_msg_encode(msg))
            return msg, bin_flag


def retr_ftp(tokens, conn_socket, logged_in, cwd, data_socket_field, pasv_flag, bin_flag):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, data_socket_field
    # Check if file refers to a directory
    path = os.path.relpath(get_pathname(tokens[1], cwd))

    if os.path.isdir(path):
        msg = '450 ' + tokens[1] + ' refers to a directory'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Check if file does not exist
    if not os.path.isfile(path):
        msg = '550 ' + tokens[1] + ' does not exist'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Attempt to establish data connection
    try:
        if pasv_flag:  # Passive Mode
            data_socket, data_host = data_socket_field.accept()
        else:  # Active Mode
            data_socket = socket(AF_INET, SOCK_STREAM)
            data_socket.connect(data_socket_field)
    except OSError:
        msg = '425 Error establishing data connection'
        conn_socket.send(str_msg_encode(msg))
        return msg, None

    msg = '150 File status ok, ready to transfer ' + tokens[1]
    conn_socket.send(str_msg_encode(msg))

    # Begin reading from file and sending data
    # Set mode to text or binary depending on type of file transferred
    file_mode = 'rt'
    if bin_flag:
        file_mode = 'rb'
    f_send = open(path, file_mode)

    size_sent = 0
    # Use write so it doesn't produce a new line (like print)
    sys.stdout.write("|")
    try:
        while True:
            sys.stdout.write("*")
            data = f_send.read(recv_buffer)
            # Check if end of transmission
            if not data or data == '' or len(data) <= 0:
                f_send.close()
                break
            else:
                if bin_flag:
                    data_socket.send(data)
                else:
                    data_socket.send(data.encode('ascii'))
                size_sent += len(data)
    except (OSError, UnicodeDecodeError):  # Invalid type set
        f_send.close()
        data_socket.close()
        msg_2 = '451 ' + tokens[1] + ' could not be transmitted'
        conn_socket.send(str_msg_encode(msg_2))
        return (msg + '\n' + msg_2), None

    sys.stdout.write("|")
    sys.stdout.write("\n")

    # Close data connection socket
    data_socket.close()
    msg_2 = '226 ' + tokens[1] + ' was successfully transmitted'
    conn_socket.send(str_msg_encode(msg_2))
    return (msg + '\n' + msg_2), None


def stor_ftp(tokens, conn_socket, logged_in, cwd, data_socket_field, pasv_flag, bin_flag, append_flag):
    # Check if logged in
    if not logged_in:
        msg = '530 Not logged in'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Check if invalid parameter size
    msg, correct_size = correct_parameter_size(tokens, conn_socket, 2)
    if not correct_size:
        return msg, data_socket_field
    # Check if file refers to a directory
    path = os.path.relpath(get_pathname(tokens[1], cwd))

    if os.path.isdir(path):
        msg = '450 ' + tokens[1] + ' refers to a directory'
        conn_socket.send(str_msg_encode(msg))
        return msg, data_socket_field
    # Attempt to establish data connection
    try:
        if pasv_flag:  # Passive Mode
            data_socket, data_host = data_socket_field.accept()
        else:  # Active Mode
            data_socket = socket(AF_INET, SOCK_STREAM)
            data_socket.connect(data_socket_field)
    except OSError:
        msg = '425 Error establishing data connection'
        conn_socket.send(str_msg_encode(msg))
        return msg, None

    msg = '150 File status ok, ready to transfer ' + tokens[1]
    conn_socket.send(str_msg_encode(msg))

    # Begin receiving data and writing to file
    # Set mode to write, append, text or binary depending on type of file transferred
    file_mode = ""
    if append_flag:
        file_mode += 'a'
    else:
        file_mode += 'w'
    if bin_flag:
        file_mode += 'b'
    else:
        file_mode += 't'

    f_recv = open(path, file_mode)
    size_recv = 0
    # Use write so it doesn't produce a new line (like print)
    sys.stdout.write("|")
    try:
        while True:
            sys.stdout.write("*")
            data = data_socket.recv(recv_buffer)
            if not bin_flag:
                data = data.decode('ascii')
            # Check if end of transmission
            if not data or data == '' or len(data) <= 0:
                f_recv.close()
                break
            else:
                f_recv.write(data)
                size_recv += len(data)
    except (OSError, UnicodeDecodeError):  # Invalid type set
        f_recv.close()
        data_socket.close()
        # Remove the corrupted file
        os.remove(path)
        msg_2 = '451 ' + tokens[1] + ' could not be transmitted'
        conn_socket.send(str_msg_encode(msg_2))
        return (msg + '\n' + msg_2), None

    sys.stdout.write("|")
    sys.stdout.write("\n")

    # Close data connection socket
    data_socket.close()
    msg_2 = '226 ' + tokens[1] + ' was successfully transmitted'
    conn_socket.send(str_msg_encode(msg_2))
    return (msg + '\n' + msg_2), None


def str_msg_encode(str_value):
    msg = str_value.encode()
    return msg


def msg_str_decode(msg, p_strip=False):
    # Print("msg_str_decode:" + str(msg))
    str_value = msg.decode()
    if p_strip:
        str_value.strip('\n')
    return str_value


# Convert pathname to correct pathname
def get_pathname(pathname, cwd=os.getcwd()):
    path = cwd
    pathname = pathname.replace('\\', '/')
    files = pathname.split('/')
    for dir in files:
        if dir is not None:
            path = os.path.join(path, dir)
    return os.path.normpath(path)


# Checks whether parameter list for command is above lower limit
def below_parameter_lower_limit(tokens, connection_socket, low):
    if len(tokens) < low:
        msg = '501 Missing parameters expected ' + str(low) + ' received ' + str(len(tokens))
        connection_socket.send(str_msg_encode(msg))
        return msg, True
    return "", False


# Checks whether parameter list for command is above lower limit
def above_parameter_upper_limit(tokens, connection_socket, high):
    if len(tokens) > high:
        msg = '501 Too many parameters expected ' + str(high) + ' received ' + str(len(tokens))
        connection_socket.send(str_msg_encode(msg))
        return msg, True
    return "", False


# Checks whether parameter list is within a bounded range
def correct_parameter_size(tokens, connection_socket, low=2, high=2):
    msg_l, is_lower = below_parameter_lower_limit(tokens, connection_socket, low)
    msg_u, is_upper = above_parameter_upper_limit(tokens, connection_socket, high)
    if is_lower:
        return msg_l, False
    if is_upper:
        return msg_u, False
    return "", True


if __name__ == "__main__":
    main()
