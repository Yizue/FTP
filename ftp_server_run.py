# FTP Server Control - author: Steve Hirabayashi
from socket import *
import sys
import os
import argparse
import configparser

# Globals
configfile = 'ftpserver\conf\server.cfg'
userfile = None
service_port = None
recv_buffer = None
server_enable = None

def main():
    global service_port, configfile, userfile, recv_buffer, server_enable

    # Parse program arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-config', action="store", dest='conf')
    parser.add_argument('-info', action="store_true", default=False)
    args = parser.parse_args()

    if args.info:
        print("Author: Steve Hirabayashi\nPID: 2247504\nThis will start and stop the FTP Server by the" +
              "Service TCP Connection\nUse -h option to get usage for this program")

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

    service_port = int(configs['FTP_SERVER']['SERVICE_PORT'])
    recv_buffer = int(configs['FTP_SERVER']['RECV_BUFFER'])

    if configs['FTP_SERVER']['SERVER_ENABLE'] == "False":
        server_enable = False
    else:
        server_enable = True

    # Catch requests to suspend/resume/end server
    while True:
        if server_enable:
            rinput = input("Enter <S> to SUSPEND server, Enter <C> to CLOSE the server: ")
            rinput = rinput.upper()
            if rinput == "S":
                ftp_connect_and_send("SUSPEND")
                server_enable = False  # Server now suspended
            if rinput == "C":
                ftp_connect_and_send("CLOSE")
                break
        else:
            rinput = input("Enter <R> to RESUME server, Enter <C> to CLOSE the server: ")
            rinput = rinput.upper()
            if rinput == "R":
                ftp_connect_and_send("RESUME")
                server_enable = True  # Server now active
            if rinput == "C":
                ftp_connect_and_send("CLOSE")
                break

    sys.exit(0)


def ftp_connect_and_send(message):
    # Create socket for start service connection
    service_socket = socket(AF_INET, SOCK_STREAM)
    service_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # Connect to server and send message
    service_socket.connect(('127.0.0.1', service_port))
    service_socket.send(message.encode())
    reply = service_socket.recv(recv_buffer).decode()
    if reply[:2] != "OK":
        print("Error: Unable to " + message.lower() + ". Exiting...")
        sys.exit(1)
    service_socket.close()


def get_pathname(pathname, cwd=os.getcwd()):
    path = cwd
    pathname = pathname.replace('\\', '/')
    files = pathname.split('/')
    for dir in files:
        if dir is not None:
            path = os.path.join(path, dir)
    return os.path.normpath(path)


if __name__ == "__main__":
    main()