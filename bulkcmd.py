#!/usr/bin/env python3

import re
import sys
import time
import signal
import getpass
import paramiko
import ipaddress
import telnetlib
import subprocess
import multiprocessing as mp

from os import getenv

auth = {
    'login':    '',
    'password': '',
    'enable':   False,
    'en_pass':  '',
    'comand':   [],
}

childlimit = 100

verb = False

debug = False

nosecure = False

telnet = False

sigExit = False

scan4first = ''

def ctrlc(signum, frame):
    global sigExit
    sigExit = True


def get2match(tn, patterns, timeout=10):
    text = b''
    if len(patterns) > 0:
        text = tn.read_until(patterns[0], timeout=timeout)
        if debug: print('DEBUG: read -->{}<-- from telnet'.format(text), file=sys.stderr)
        for i in range(len(patterns)):
            if len(re.findall(patterns[i], text)) > 0:
                return True, i, text + b'\n'
    return False, 0, text


def getsec2match(ssh, patterns, timeout=10):
    text = b''
    if len(patterns) > 0:
        ssh.settimeout(timeout)
        while True:
            try:
                text += ssh.recv(1024)
            except Exception as err:
                break
        if debug: print('DEBUG: read -->{}<-- from SSH'.format(text), file=sys.stderr)
        for i in range(len(patterns)):
            if len(re.findall(patterns[i], text)) > 0:
                return True, i, text
    return False, 0, text


def text2strings(ip, text):
    res = []
    for line in re.split(r'\n', text.decode('ascii')):
        line = re.sub(r'\x08|\r', '', line)
        if line == '':
            continue
        res.append(ip + '\t' + line.strip())
    return res


def child(ip, c, q):
    global sigExit
    res = []
    try:
        login = False
        tn = telnetlib.Telnet(ip, 23, 5)
        match, indx, text = get2match(tn, [b'[Ll]ogin:\s*$', b'[Uu]ser[Nn]ame:\s*$', b'[Pp]ass[Ww]ord:\s*$'])
        if match:
            if sigExit: exit()
            if indx == 0 or indx == 1:
                if verb: print('{}\tproc {}: send login {}'.format(ip, c, auth['login']))
                tn.write(auth['login'].encode('ascii') + b'\n')
                match, indx, text = get2match(tn, [b'[Pp]ass[Ww]ord:\s*$'])
                if match:
                    if sigExit: exit()
                    if verb: print('{}\tproc {}: send password'.format(ip, c))
                    tn.write(auth['password'].encode('ascii') + b'\n')
                    match, indx, text = get2match(tn, [b'>\s*$', b'#\s*$'])
                    if match:
                        if sigExit: exit()
                        if verb: print('{}\tproc {}: user {} logged in'.format(ip, c, auth['login']))
                        if indx == 0:
                            if 'enable' in auth.keys() and auth['enable']:
                                if verb: print('{}\tproc {}: send command enable for login {}'.format(ip, c, auth['login']))
                                tn.write(b'enable\n')
                                match, indx, text = get2match(tn, [b'[Pp]ass[Ww]ord:\s*$', b'#\s*$'])
                                if match:
                                    if sigExit: exit()
                                    if indx == 0:
                                        if verb: print('{}\tproc {}: send enable password'.format(ip, c))
                                        tn.write(auth['en_pass'].encode('ascii') + b'\n')
                                        match, indx, text = get2match(tn, [b'#\s*$'])
                                        if match:
                                            if verb: print('{}\tproc {}: user {} enter privileged mode.'.format(ip, c, auth['login']))
                                            login = True
                                    elif indx == 1:
                                        if verb: print('{}\tproc {}: user {} enter privileged mode.'.format(ip, c, auth['login']))
                                        login = True
                                else:
                                    if verb: print('{}\tproc {}: user {} not enter privileged mode.'.format(ip, c, auth['login']))
                            else:
                                login = True
                        elif indx == 1:
                            if verb: print('{}\tproc {}: user {} logged in'.format(ip, c, auth['login']))
                            login = True
            elif indx == 2:
                if verb: print('{}\tproc {}: send password'.format(ip, c))
                tn.write(auth['password'].encode('ascii') + b'\n')
                match, indx, text = get2match(tn, [b'>\s*$', b'#\s*$'])
                if match:
                    if sigExit: exit()
                    if verb: print('{}\tproc {}: logged in'.format(ip, c))
                    if indx == 0:
                        if 'enable' in auth.keys() and auth['enable']:
                            if verb: print('{}\tproc {}: send command enable'.format(ip, c))
                            tn.write(b'enable\n')
                            match, indx, text = get2match(tn, [b'[Pp]ass[Ww]ord:\s*$', b'#\s*$'])
                            if match:
                                if sigExit: exit()
                                if indx == 0:
                                    if verb: print('{}\tproc {}: send enable password'.format(ip, c))
                                    tn.write(auth['en_pass'].encode('ascii') + b'\n')
                                    match, indx, text = get2match(tn, [b'#\s*$'])
                                    if match:
                                        if verb: print('{}\tproc {}: enter privileged mode.'.format(ip, c))
                                        login = True
                                elif indx == 1:
                                    if verb: print('{}\tproc {}: enter privileged mode.'.format(ip, c))
                                    login = True
                            else:
                                if verb: print('{}\tproc {}: not enter privileged mode.'.format(ip, c))
                        else:
                            login = True
                    elif indx == 1:
                        if verb: print('{}\tproc {}: enter privileged mode.'.format(ip, c))
                        login = True
        if sigExit: exit()
        if login:
            for cmd in auth['comand']:
                if verb: print('{}\tproc {}: send comand "{}"'.format(ip, c, cmd))
                tn.write(cmd.encode('ascii') + b'\n')
                match, indx, text = get2match(tn, [b'>\s*$', b'#\s*$'], 1)
                res.extend(text2strings(ip, text))
                lastText = b''
                pg = 0
                while(not match):
                    if sigExit: exit()
                    pg += 1
                    if verb: print('{}\tproc {}: read page {}'.format(ip, c, pg))
                    tn.write(b' ')
                    match, indx, text = get2match(tn, [b'>\s*$', b'#\s*$'], 1)
                    res.extend(text2strings(ip, text))
                    if text == lastText:
                        break
                    lastText = text
            tn.write(b'exit\n')
        else:
            print('{}\tproc {}: Error: login failed'.format(ip, c))
            print('{}\tproc {}: Error: Can`t enter to device'.format(ip, c), file=sys.stderr)
        tn.close()
    except Exception as err:
        print('{}\tproc {}: Error: {}'.format(ip, c, err), file=sys.stderr)
    q.put(res)
    while(not q.empty()):
        if sigExit: exit()
        time.sleep(1)
    if verb: print('{}\tproc {}: Exit'.format(ip, c))


def secchild(ip, c, q):
    global sigExit
    res = []
    try:
        login = False
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(hostname=ip, username=auth['login'], password=auth['password'], port=22, timeout=5)
        except paramiko.ssh_exception.AuthenticationException:
            print('{}\tproc {}: Error: Authentication Failure'.format(ip, c), file=sys.stderr)
            return
        except Exception as err:
            if nosecure:
                if verb: print('{}\tproc {}: No SSH connection available or timeout. Try Telnet'.format(ip, c))
                child(ip, c, q)
                return
            else:
                print('{}\tproc {}: Error: {}'.format(ip, c, err), file=sys.stderr)
            return
        ssh = client.invoke_shell()
        match, indx, text = getsec2match(ssh, [b'>\s*$', b'#\s*$'])
        if match:
            if sigExit: exit()
            if verb: print('{}\tproc {}: user {} logged in'.format(ip, c, auth['login']))
            if indx == 0:
                if 'enable' in auth.keys() and auth['enable']:
                    if verb: print('{}\tproc {}: send command enable for login {}'.format(ip, c, auth['login']))
                    ssh.send('enable\n')
                    match, indx, text = getsec2match(ssh, [b'[Pp]ass[Ww]ord:\s*$', b'#\s*$'])
                    if match:
                        if sigExit: exit()
                        if indx == 0:
                            if verb: print('{}\tproc {}: send enable password'.format(ip, c))
                            ssh.send(auth['en_pass'] + '\n')
                            match, indx, text = getsec2match(ssh, [b'#\s*$'])
                            if match:
                                if verb: print('{}\tproc {}: user {} enter privileged mode.'.format(ip, c, auth['login']))
                                login = True
                        elif indx == 1:
                            if verb: print('{}\tproc {}: user {} enter privileged mode.'.format(ip, c, auth['login']))
                            login = True
                    else:
                        if verb: print('{}\tproc {}: user {} not enter privileged mode.'.format(ip, c, auth['login']))
                else:
                    login = True
            elif indx == 1:
                if verb: print('{}\tproc {}: user {} logged in'.format(ip, c, auth['login']))
                login = True

        if sigExit: exit()
        if login:
            for cmd in auth['comand']:
                if verb: print('{}\tproc {}: send comand "{}"'.format(ip, c, cmd))
                ssh.send(cmd + '\n')
                match, indx, text = getsec2match(ssh, [b'>\s*$', b'#\s*$'], 1)
                res.extend(text2strings(ip, text))
                lastText = b''
                pg = 0
                while(not match):
                    if sigExit: exit()
                    pg += 1
                    if verb: print('{}\tproc {}: read page {}'.format(ip, c, pg))
                    ssh.send(' ')
                    match, indx, text = getsec2match(ssh, [b'>\s*$', b'#\s*$'], 1)
                    res.extend(text2strings(ip, text))
                    if text == lastText:
                        break
                    lastText = text
            ssh.send('exit\n')
        else:
            print('{}\tproc {}: Error: login failed'.format(ip, c))
            print('{}\tproc {}: Error: Can`t enter to device'.format(ip, c), file=sys.stderr)
        client.close()
    except Exception as err:
        print('{}\tproc {}: Error: {}'.format(ip, c, err), file=sys.stderr)
    q.put(res)
    while(not q.empty()):
        if sigExit: exit()
        time.sleep(1)
    if verb: print('{}\tproc {}: Exit'.format(ip, c))


def proc(iplist):
    global sigExit
    childs = []
    c = 0
    print('\nUsername:', auth['login'])
    if telnet:
        print("\nUse Telnet protocol")
    elif nosecure:
        print("\nUse SSH or Telnet if SSH connection filed")
    else:
        print("\nUse only SSH protocol")
    print("\nIP List: {} hosts".format(len(iplist)))
    if len(iplist) > 12:
        print("\nIP List: {}  ...  {}\n".format(' '.join(iplist[0:5]), ' '.join(iplist[len(iplist)-5:])))
    else:
        print("\nIP List: {}\n".format(' '.join(iplist)))

    for ip2scan in scan4first.split(','):
        if ip2scan != '':
            if verb: print("Scaning {} by nmap".format(ip2scan))
            rescmd = subprocess.run(['/usr/bin/env', 'nmap', '-sP', ip2scan], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            cmdout = rescmd.stdout.decode('utf-8') + rescmd.stderr.decode('utf-8')
        if sigExit:
            exit()

    while True:
        newChilds = []
        while len(childs) > 0:
            Process, cc, q = childs.pop()
            if Process.is_alive():
                newChilds.append([Process, cc, q])
            else:
                Process.join()
        childs = newChilds

        if len(childs) < childlimit:
            for i in range(childlimit-len(childs)):
                if c < len(iplist):
                    try:
                        q = mp.SimpleQueue()
                        Process = None
                        if telnet:
                            Process = mp.Process(target=child, args=(iplist[c], c, q), group=None, name=None, daemon=False)
                        else:
                            Process = mp.Process(target=secchild, args=(iplist[c], c, q), group=None, name=None, daemon=False)
                        Process.start()
                        childs.append([Process, c, q])
                        if verb: print("{}\tproc {}: Start new child processes and wait for answer".format(iplist[c], c), file=sys.stderr)
                        c += 1
                    except Exception as err:
                        print("{}\tproc {}: Error start subprocess: {}".format(iplist[c], c, err), file=sys.stderr)

        if len(childs) > 0:
            for buf in childs:
                Process, cc, q = buf
                if Process.is_alive():
                    if q.empty():
                        continue
                    if verb: print('Main: read result from proc {}'.format(cc), file=sys.stderr)
                    res = q.get()
                    Process.join()
                    if verb: print("Main: proc {} answer:".format(cc), file=sys.stderr)
                    for buf in res:
                        print(buf)
        else:
            break

        if sigExit:
            print("\n\nTerminating all child processes.\n")
            for arr in childs:
                Process, cc, q = arr
                Process.terminate()
            while True:
                flag = True
                for arr in childs:
                    Process, cc, q = arr
                    if Process.is_alive():
                        flag = False
                        try:
                            if not q.empty():
                                res = q.get()
                        except Exception as err:
                            print("Main: proc {}: Error: {}".format(cc, err), file=sys.stderr)
                    else:
                        Process.join()
                if flag:
                    break
                time.sleep(1)
            break

        time.sleep(1)

def helpmess():
    print('\n\n{} [-l child_limit] [-u login] [-p[ass] password] [-v] [-t] [-n[osec]] [-e[nable]] [-ep[ass] password] [-c[md] "command1"] [-c[md] "command2"] ipnet1[[,ipnet2] ipnet3 ... ipnetX]'.format(sys.argv[0]))
    print("""

    Скрипт на Python, который позволяет выполнить одну и ту же (или несколько) команду на большом количестве устройств под одной учетной записью через SSH или (с ключом -t) Telnet.
    Если соединение по SSH будет неудачным, то ключ -n позволит сделать попытку еще и через Telnet.
    В случае необходимости выполнить команду в привелигированном режиме, для входа в enable используйте ключ -e.

    ip1[[,ip2] ip3 ... ipX]
    ipnet1[[,ipnet2] ipnet3 ... ipnetX]

        список IP адресов или сетей в формате x.x.x.x/prefix, разделенных символом ',' или ' '.

    -c, -cmd "command"
        указать выполняемую команду. Обязательно в кавычках, если команда состоит из нескольких слов.
        допускается применение ключа несколько раз для выполнения нескольких команд подряд.
        если ключ пропущен, то по умолчанию выполняется команда 'sh ver'

    -l num
        количество одновременных параллельных процессов
        по умолчанию 100

    -n, -nosec
        попробовать использовать Telnet, если возникнет ошибка соединения по SSH (кроме ошибок авторизации).
        бесполезен, если используется ключ -t

    -t
        использовать только Telnet вместо SSH

    -u username
        указать имя пользователя

    -p, -pass
        запросить пароль пользователя

    -e, -enable
        ввести команду enable

    -ep, -epass
        запросить пароль на enable

    -v
        отображать ход выполнения процесса
    """)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, ctrlc)
    signal.signal(signal.SIGTERM, ctrlc)
    mp.set_start_method('fork')

    lenargv = len(sys.argv)
    iplist = []
    if lenargv > 1:
        i = 1
        while(i<lenargv):
            if sys.argv[i] == '-u' and i+1 < lenargv:
                auth['login'] = sys.argv[i+1]
                i += 1
            elif sys.argv[i] == '-pass' and i+1 < lenargv:
                auth['password'] = sys.argv[i+1]
                i += 1
            elif sys.argv[i] == '-p' and i+1 < lenargv:
                auth['password'] = sys.argv[i+1]
                i += 1
            elif sys.argv[i] == '-v':
                verb = True
            elif sys.argv[i] == '-t':
                telnet = True
            elif sys.argv[i] == '-d':
                verb = True
                debug = True
            elif sys.argv[i] == '-n':
                nosecure = True
            elif sys.argv[i] == '-nosec':
                nosecure = True
            elif sys.argv[i] == '-s' and i+1 < lenargv:
                scan4first = sys.argv[i+1]
                i += 1
            elif sys.argv[i] == '-enable':
                auth['enable'] = True
            elif sys.argv[i] == '-e':
                auth['enable'] = True
            elif sys.argv[i] == '-epass' and i+1 < lenargv:
                auth['en_pass'] = sys.argv[i+1]
                i += 1
            elif sys.argv[i] == '-ep' and i+1 < lenargv:
                auth['en_pass'] = sys.argv[i+1]
                i += 1
            elif sys.argv[i] == '-l' and i+1 < lenargv:
                if sys.argv[i+1].isdigit():
                    childlimit = int(sys.argv[i+1])
                i += 1
            elif sys.argv[i] == '-cmd' and i+1 < lenargv:
                auth['comand'].append(sys.argv[i+1])
                i += 1
            elif sys.argv[i] == '-c' and i+1 < lenargv:
                auth['comand'].append(sys.argv[i+1])
                i += 1
            elif sys.argv[i] == '-h':
                helpmess()
                exit()
            else:
                arr = sys.argv[i].split(',')
                for ip in arr:
                    if ip != '':
                        iplist.append(ip)
            i +=1

    ip4proc = []
    if len(iplist) > 0:
        chk = set()
        for ip in iplist:
            try:
                for host in list(ipaddress.ip_network(ip).hosts()):
                    ipaddr = str(host)
                    if ipaddr not in chk:
                        ip4proc.append(ipaddr)
                        chk.add(ipaddr)
            except Exception as err:
                print('Error: wrong format network ipaddress:', ip, file=sys.stderr)
                exit()
        chk.clear()
    else:
        helpmess()
        exit()

    if len(ip4proc) > 0:
        if 'login' not in auth.keys() or auth['login'] == '':
            auth['login'] = getenv('LOGNAME')
        if auth['login'] == 'root':
            print("\nUser root is not allowed. Use -u key\n")
            exit()
        if 'password' not in auth.keys() or auth['password'] == '':
            print('Enter login password for user {}'.format(auth['login']), file=sys.stderr)
            auth['password'] = getpass.getpass()
        if auth['enable'] and auth['en_pass'] == '':
            print('Enter enable password for user {}'.format(auth['login']), file=sys.stderr)
            auth['en_pass'] = getpass.getpass()
        if len(auth['comand']) == 0:
            auth['comand'].append('sh ver')
        proc(ip4proc)

    else:
        print('Enter list of IP-addresses')

    exit()
