#!/usr/bin/env python3
from src.tcp_replay import tcp_replay, replay_usage
from src.tcp_reset import tcp_reset, reset_usage
from src.Client import Client
from os import system


def usage():
    pass


def main():
    cmd = ''
    client = None
    valid_opt = ['reset', 'replay', 'set', 'both', 'mac', 'ip', 'port',
                 'client', 'victim', 'all', 'pcap', 'exit', 'show',
                 'interface', 'clear']

    while 'exit' not in cmd:
        cmd = input('Enter Command: ').lower().split()
        if not all(map(lambda x: x in valid_opt, cmd)):
            print("ERROR invalid command: {}".format(
                ' '.join(list(filter(lambda x: x not in valid_opt, cmd)))))
            usage()
            continue

        if 'reset' in cmd:
            if 'help' in cmd:
                reset_usage()
            else:
                if client:
                    client.add_typ(0)
                else:
                    client = Client(0)
        elif 'replay' in cmd:
            if 'help' in cmd:
                replay_usage()
            else:
                if client:
                    client.add_typ(1) 
                else:
                    client = Client(1)
        elif 'show' in cmd:
            print(client)
        elif 'clear' in cmd:
            system('clear')
        elif '' in cmd:
            pass
        elif 'set' in cmd:
            if not client:
                client = Client()
            client.update(cmd[1:], True)
        elif 'help' in cmd:
            usage()
        elif 'exit' in cmd:
            continue
        else:
            print('ERROR invalid option')
            usage()


# main call
if __name__ == '__main__':
    main()
