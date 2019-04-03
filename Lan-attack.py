#!/usr/bin/env python3
from src.tcp_replay import tcp_replay, replay_usage
from src.tcp_reset import tcp_reset, reset_usage
from src.Clientnew import Client
from os import system


def usage():
    print('usage')


def main():
    cmd = ''
    client = Client()
    valid_opt = ['reset', 'replay', 'set', 'both', 'mac', 'ip', 'port',
                 'client', 'victim', 'all', 'pcap', 'exit', 'show',
                 'interface', 'clear', 'add', 'export', 'import']

    while 'exit' not in cmd:
        cmd = input('Enter Command: ').lower().split()
        if 'add' not in cmd and 'set' not in cmd and not all(map(lambda x: x in valid_opt, cmd)):
            print("ERROR invalid command: {}".format(
                ' '.join(list(filter(lambda x: x not in valid_opt, cmd)))))
            usage()
            continue

        if 'reset' in cmd:
            if 'help' in cmd:
                reset_usage()
            else:
                client.add_typ(0)
        elif 'replay' in cmd:
            if 'help' in cmd:
                replay_usage()
            else:
                client.add_typ(1)
        elif 'show' in cmd:
            if 'help' in cmd:
                pass
            else:
                print(client)

        elif 'add' in cmd:
            client.add_vic(cmd[1])

        elif 'clear' in cmd:
            system('clear')

        elif '' in cmd:
            pass

        elif 'export' in cmd:
            client.exprt(cmd[1])

        elif 'import' in cmd:
            client.imprt(cmd[1])

        elif 'set' in cmd:
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
