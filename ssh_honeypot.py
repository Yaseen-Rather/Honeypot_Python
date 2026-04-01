#libraries

import logging
from logging.handlers import RotatingFileHandler

import socket

import paramiko

import threading

from collections import defaultdict

# Constants

logging_format = logging.Formatter('%(asctime)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"

host_key = paramiko.RSAKey(filename='server.key')


# Failed Attempts 

failed_attempts = defaultdict(int)
ATTEMPT_THRESHOLD = 3

#loggers & logging files

funnel_logger = logging.getLogger('FunnelLogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=200000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=200000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

# Emulated Shell

# Used Claude to generate 20 commands emulated shell

# I am still learning fabric and paramiko properly thats why i am not yet able to deply it on cloud to collect the real world data. It will be my next step for this honeypot project.

def emulated_shell(channel, client_ip):
    channel.send(b'corpuser1@corporate-jumpbox2:~$ ')
    command = b""
    while True:
        char = channel.recv(1)
        channel.send(char)
        if not char:
            channel.close()
            return

        command += char

        if char == b'\r':
            cmd = command.strip()

            # Navigation & System

            if cmd == b'exit' or cmd == b'logout':
                channel.send(b'\nGoodbye!\r\n')
                channel.close()
                return

            elif cmd == b'pwd':
                response = b'\n/home/corpuser1\r\n'

            elif cmd.startswith(b'cd'):
                response = b'\r\n'  

            elif cmd == b'whoami':
                response = b'\ncorpuser1\r\n'

            elif cmd == b'uname -a':
                response = b'\nLinux corporate-jumpbox2 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 GNU/Linux\r\n'

            elif cmd == b'hostname':
                response = b'\ncorporate-jumpbox2\r\n'

            elif cmd == b'uptime':
                response = b'\n 09:32:41 up 47 days,  3:21,  1 user,  load average: 0.12, 0.08, 0.05\r\n'

            elif cmd == b'date':
                response = b'\nTue Nov 14 09:32:41 UTC 2023\r\n'

            # File System

            elif cmd == b'ls' or cmd == b'ls -la':
                response = (
                    b'\ntotal 32'
                    b'\ndrwxr-xr-x 3 corpuser1 corpuser1 4096 Nov 14 08:12 .'
                    b'\ndrwxr-xr-x 5 root      root      4096 Nov 10 12:00 ..'
                    b'\n-rw------- 1 corpuser1 corpuser1  220 Nov 10 12:00 .bash_history'
                    b'\n-rw-r--r-- 1 corpuser1 corpuser1  807 Nov 10 12:00 .bashrc'
                    b'\n-rw-r--r-- 1 corpuser1 corpuser1  612 Nov 14 08:12 jumpbox1.conf'
                    b'\n-rw-r--r-- 1 corpuser1 corpuser1  128 Nov 14 08:12 network_notes.txt'
                    b'\ndrwxr-xr-x 2 corpuser1 corpuser1 4096 Nov 10 12:00 scripts\r\n'
                )

            elif cmd == b'cat jumpbox1.conf':
                response = (
                    b'\n# Jumpbox Configuration'
                    b'\nhost=corporate-jumpbox2'
                    b'\nip=10.0.0.5'
                    b'\ngateway=10.0.0.1'
                    b'\nadmin_contact=admin@corp.internal'
                    b'\nlast_updated=2023-11-14\r\n'
                )

            elif cmd == b'cat network_notes.txt':
                response = (
                    b'\n# Internal Network Notes'
                    b'\nDo not share this file outside the team.'
                    b'\nVPN subnet: 192.168.10.0/24'
                    b'\nDB server: 10.0.0.12\r\n'
                )

            elif cmd == b'cat .bash_history':
                response = (
                    b'\nssh admin@10.0.0.12'
                    b'\nls /var/log'
                    b'\nsudo cat /etc/passwd'
                    b'\npwd'
                    b'\nexit\r\n'
                )

            # Network

            elif cmd == b'ifconfig' or cmd == b'ip a':
                response = (
                    b'\neth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\r\n'
                    b'        inet 10.0.0.5  netmask 255.255.255.0  broadcast 10.0.0.255\r\n'
                    b'        inet6 fe80::215:5dff:fe01:1  prefixlen 64\r\n'
                    b'        ether 00:15:5d:01:00:01  txqueuelen 1000\r\n\r\n'
                    b'lo: flags=73<UP,LOOPBACK,RUNNING> mtu 65536\r\n'
                    b'        inet 127.0.0.1  netmask 255.0.0.0\r\n\r\n'
                )

            elif cmd == b'netstat -an' or cmd == b'ss -an':
                response = (
                    b'\nProto Recv-Q Send-Q Local Address     Foreign Address   State\r\n'
                    b'tcp        0      0 0.0.0.0:22        0.0.0.0:*         LISTEN\r\n'
                    b'tcp        0      0 10.0.0.5:22       10.0.0.1:54312    ESTABLISHED\r\n'
                )

            elif cmd == b'ping':
                response = b'\nUsage: ping <hostname>\r\n'

            # Process & System Info

            elif cmd == b'ps aux' or cmd == b'ps':
                response = (
                    b'\nUSER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n'
                    b'root         1  0.0  0.1  16952  1076 ?        Ss   Nov10   0:02 /sbin/init\r\n'
                    b'root       512  0.0  0.2  72296  2260 ?        Ss   Nov10   0:00 /usr/sbin/sshd\r\n'
                    b'corpuser1 1024  0.0  0.1  21432  1980 pts/0    Ss   09:31   0:00 -bash\r\n'
                )

            elif cmd == b'env':
                response = (
                    b'\nUSER=corpuser1'
                    b'\nHOME=/home/corpuser1'
                    b'\nSHELL=/bin/bash'
                    b'\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
                    b'\nLANG=en_US.UTF-8\r\n'
                )

            elif cmd == b'id':
                response = b'\nuid=1001(corpuser1) gid=1001(corpuser1) groups=1001(corpuser1)\r\n'


            # Sensitive / Trap commands

            elif cmd == b'sudo su' or cmd == b'sudo -i' or cmd.startswith(b'sudo'):
                response = b'\n[sudo] password for corpuser1: \r\nSorry, try again.\r\n'
                creds_logger.info(f'[ALERT] {client_ip} attempted privilege escalation: {cmd}')
                funnel_logger.warning(f'[ALERT] {client_ip} attempted sudo/privilege escalation')

            elif cmd == b'cat /etc/passwd':
                response = (
                    b'\nroot:x:0:0:root:/root:/bin/bash\r\n'
                    b'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n'
                    b'corpuser1:x:1001:1001::/home/corpuser1:/bin/bash\r\n'
                )
                creds_logger.info(f'[ALERT] {client_ip} accessed /etc/passwd')
                funnel_logger.warning(f'[ALERT] {client_ip} attempted to read /etc/passwd')

            elif cmd == b'cat /etc/shadow':
                response = b'\ncat: /etc/shadow: Permission denied\r\n'
                creds_logger.info(f'[ALERT] {client_ip} attempted to read /etc/shadow')
                funnel_logger.warning(f'[ALERT] {client_ip} attempted to read /etc/shadow')

            elif cmd.startswith(b'wget') or cmd.startswith(b'curl'):
                response = b'\nbash: permission denied\r\n'
                creds_logger.info(f'[ALERT] {client_ip} attempted download: {cmd}')
                funnel_logger.warning(f'[ALERT] {client_ip} attempted to download a file: {cmd}')

            elif cmd == b'help':
                response = (
                    b'\nShell Commands Available:\r\n'
                    b'  Navigation : cd, pwd, ls, ls -la\r\n'
                    b'  System     : whoami, id, hostname, uname -a, uptime, date\r\n'
                    b'  Network    : ifconfig, ip a, netstat -an, ss -an\r\n'
                    b'  Files      : cat <file>, env\r\n'
                    b'  Process    : ps, ps aux\r\n'
                    b'  Other      : exit, logout, help\r\n'
                )

            # Unknown command

            else:
                response = b'\n' + bytes(cmd) + b': command not found\r\n'
                creds_logger.info(f'Unknown command by {client_ip}: {cmd}')

            # Log all commands except unknown

            if cmd not in [b'exit', b'logout', b'help'] and not cmd.startswith(b'sudo') \
               and cmd not in [b'cat /etc/passwd', b'cat /etc/shadow'] \
               and not cmd.startswith(b'wget') and not cmd.startswith(b'curl'):
                creds_logger.info(f'Command {cmd} executed by {client_ip}')

            channel.send(response)
            channel.send(b'corpuser1@corporate-jumpbox2:~$ ')
            command = b""


# SSH Server + Socket

class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password

    def check_channel_request(self, kind: str, chanin: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auth(self):
        return "password"

    def check_auth_password(self, username, password):

        funnel_logger.info(f'Client {self.client_ip} attempted connection with '
                        f'username: {username}, password: {password}')
        creds_logger.info(f'{self.client_ip}, {username}, {password}')

        # Counting failed attempts

        if self.input_username is not None and self.input_password is not None:

            if username == self.input_username and password == self.input_password:
                failed_attempts[self.client_ip] = 0  
                return paramiko.AUTH_SUCCESSFUL

            else:
                failed_attempts[self.client_ip] += 1
                if failed_attempts[self.client_ip] >= ATTEMPT_THRESHOLD:
                    funnel_logger.warning(f'[ALERT] {self.client_ip} has made '
                                        f'{failed_attempts[self.client_ip]} failed attempts — '
                                        f'possible brute force attack!')
                    print(f'\n[!!!] ALERT: {self.client_ip} — brute force suspected!')
                return paramiko.AUTH_FAILED

        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        command = str(command)
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened.")
            return

        standard_banner = "Welcome to Ubuntu 22.04 LTS (Jammy Jellyfish)!\r\n\r\n"
        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(error)
        print("!!! Error !!!")

    finally:
        try:
            transport.close()
        except Exception as error:
            print(error)
            print("!!! Error !!!")
        client.close()


# Provision SSH-based Honeypot

def honeypot(address, port, username, password):

    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()

        except Exception as error:
            print(error)