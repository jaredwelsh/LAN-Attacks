#!/usr/bin/env python3
from src.tcp_replay import tcp_replay, replay_usage
from src.tcp_reset import tcp_reset, reset_usage
# from src.deauth import deauth, deauth_usage
from src.Client import Client
from os import system


def usage(commands=True):
    usg = '\nPython-Based Network Lan Attacks Using Scapy\n\n'
    if commands:
        usg += 'List of Commands:\n'
        usg += '\tadd\t[name]\t\t\tadd a new victim\n'
        usg += '\texport\t[path]\t\t\texport current state to file\n'
        usg += '\timport\t[path]\t\t\timport state from file\n'
        usg += '\tpcap\t[path]\t\t\tadd a pcap file\n'
        usg += '\tset\t[name][options]\t\tset a victims value\n'
        usg += '\treplay\t\t\t\tsetup a replay attack\n'
        usg += '\treset\t\t\t\tsetup a reset attack\n'
        usg += '\tshow\t\t\t\tprint out the current state\n'
        usg += '\tclear\t\t\t\tclear the terminal\n'
        usg += '\texit\t\t\t\texit the program'
        # 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    else:
        usg += 'This tool is built around a class called Client. This class contains a list of\n'
        usg += 'runnable attacks, a pcap file and the current interface. Additionally it has a\n'
        usg += 'dictionary of NetAttrs called victims. This is the heart of the program.\n'
        usg += 'NetAtts is a class that contains a mac, ip, port and name. This provides the\n'
        usg += 'Lan-Attack with the fields it needs to spoof messages to run attacks. New\n'
        usg += 'victims can be added using the add command. A name is given to the victim, which\n'
        usg += 'is used for reference in set and run. Export will export all the current values\n'
        usg += 'to a file so they can be imported by the program if you want to save data for\n'
        usg += 'later. Set accepts lists of names and options. For example, valid command\n\n'
        usg += '\tset vic1 mac ip vic2 port vic3 all\n\n'
        usg += 'This will set the fields as expected. To add the values\n'
        usg += 'in the command itself, you can add colons to the command\n\n'
        usg += '\tset vic1 mac ip: 192.186.1.1 vic2 port: 4409 vic3 all\n\n'
        usg += 'A pcap can also be used to set values\n\n'
        usg += '\tset vic1 pcap vic2 port: 4409 vic3 all\n'
        usg += '\tset vic1 pcap: ../example.pcap vic2 port: 4409 vic3 all\n\n'
        usg += 'Valid options for set are: mac, ip, port, pcap, all.\n\n'
        # usg += 'Add also has additional function. You can set fields in add\n'
        # usg += '\tadd vic1 set ip vic2\n\n'
        usg += 'Show will show all fields of all victims as well as the pcap and interface.\n'
        usg += 'The general flow of this program is add, followed by declaring an attack followed\n'
        usg += 'by running the attack. It is important to know, that each attack will prompt you\n'
        usg += 'with any fields you are missing. You do not need to know what attacks require what\n'
        usg += 'fields beforehand.\n'
    print(usg)


def main():
    typ_func = {
        -1: None,
        'reset': tcp_reset,
        'replay': tcp_replay,
        'deauth': None
        # 2:  deauth
    }

    cmd = ''
    # prev_cmds = []
    client = Client()
    valid_opt = [
        'add', 'all', 'clear', 'exit', 'export', 'import', 'interface', 'ip',
        'mac', 'pcap', 'port', 'replay', 'reset', 'set', 'setup', 'show',
        'help', 'run'
    ]

    while 'exit' not in cmd:
        cmd = input('Enter Command: ').lower().split()
        if (not any(
                map(lambda x: x in ('add', 'set', 'import', 'export', 'run'),
                    cmd)) and not all(map(lambda x: x in valid_opt, cmd))):
            print("ERROR invalid command: {}".format(' '.join(
                list(filter(lambda x: x not in valid_opt, cmd)))))
            usage()
            continue

        # prev_cmds.insert(0, cmd)

        if 'run' in cmd:
            client.run(typ_func[cmd[1]], cmd[2], cmd[3])

        elif 'setup' in cmd:
            if 'reset' in cmd:
                client.add_typ(0)
            elif 'replay' in cmd:
                client.add_typ(1)

        elif 'reset' in cmd and 'help' in cmd:
            reset_usage()

        elif 'replay' in cmd and 'help' in cmd:
            replay_usage()

        elif 'show' in cmd:
            print(client)

        elif 'add' in cmd:
            client.add_vic(cmd[1:])

        elif 'clear' in cmd:
            system('clear')

        elif '' in cmd:
            continue

        elif 'export' in cmd:
            client.exprt(cmd[1])

        elif 'import' in cmd:
            client.imprt(cmd[1])

        elif 'set' in cmd:
            client.update(cmd[1:], True)

        elif 'help' in cmd:
            usage(commands=False)

        elif 'exit' in cmd:
            continue


# main call
if __name__ == '__main__':
    main()
