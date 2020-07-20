#!/usr/bin/python3
"""
Forked From BooFuzz, Sulley, and Fuzzowski
https://github.com/jtpereyda/boofuzz
http://www.github.com/nccgroup/fuzzowski

Licensed under GNU General Public License v2.0 - See LICENSE.txt
"""

import argparse
import random

from epf import *
from epf.fuzzers import IFuzzer
from epf.restarters import IRestarter
from epf.monitors import IMonitor, IThreadMonitor
from epf.session import Session

logo = """
(==(     )==)
 `-.`. ,',-'
    _,-'"
 ,-',' `.`-.
(==(     )==)
 `-.`. ,',-'
    _,-'"       Evolutionary Protocol Fuzzer
 ,-',' `.`-.      EPF
(==(     )==)"""

logo = """
`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"
   `=`,'=/     `=`,'=/     `=`,'=/     `=`,'=/
     y==/        y==/        y==/        y==/
   ,=,-<=`.    ,=,-<=`.    ,=,-<=`.    ,=,-<=`.
,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_
        - Evolutionary Protocol Fuzzer -
"""


class EPF(object):

    def __init__(self):
        self.session = None  # ok

        self._init_argparser()  # ok
        self.args = self._parse_args()  # ok

        self.target = Target(  # ok
            connection=SocketConnection(  # ok
                            host=self.args.host,
                            port=self.args.port,
                            proto=self.args.protocol,
                            bind=self.args.bind,
                            send_timeout=self.args.send_timeout,
                            recv_timeout=0.1
                            #recv_timeout=self.args.recv_timeout
            )
        )

        self.session = Session(
            sleep_time=self.args.sleep_time,
            # restart_interval=0,
            crash_threshold_request=self.args.crash_threshold_request,
            crash_threshold_element=self.args.crash_threshold_element,
            restart_sleep_time=self.args.restart_sleep_time,
            # fuzz_loggers=None,
            receive_data_after_each_request=self.args.receive_data_after_each_request,
            check_data_received_each_request=self.args.check_data_received_each_request,
            receive_data_after_fuzz=self.args.receive_data_after_fuzz,
            ignore_connection_issues_after_fuzz=self.args.ignore_connection_issues_after_fuzz,
            target=self.target,
            restarter=self.restart_module,
            monitors=self.monitors,
            new_connection_between_requests=self.args.new_connection_between_requests,
            transmit_full_path=self.args.transmit_full_path,
            # reproducibility
            fuzz_protocol=self.args.fuzz_protocol,
            prng_seed=self.args.prng_seed
        )

        # # Connect nodes of graph
        # if self.args.fuzz_protocol == 'raw' and self.fuzz_requests is not None:
        #     requests = self._generate_requests_from_strings(self.fuzz_requests)
        #     for i in range(0, len(requests)):
        #         if i == 0:
        #             self.session.connect(requests[i])
        #         if len(requests) > 1:
        #             self.session.connect(requests[i], requests[i + 1])

        # elif self.fuzz_methods is not None:
        #     for fuzz_method in self.fuzz_methods:
        #         fuzz_method(self.session)
        # else:
        #     raise Exception("Impossibru!")

    # --------------------------------------------------------------- #

    def _init_argparser(self):
        """
        Initializes the argparser inside self.parser
        """

        self.parser = argparse.ArgumentParser(
            description=str(logo),
            formatter_class=argparse.RawTextHelpFormatter
        )

        self.parser.add_argument("host", help="Destination Host")
        self.parser.add_argument("port", type=int, help="Destination Port")
        conn_grp = self.parser.add_argument_group('Connection Options')
        conn_grp.add_argument("-p", "--protocol", dest="protocol", help="Protocol (Default tcp)", default='tcp',
                              choices=['tcp', 'udp', 'ssl'])
        conn_grp.add_argument("-b", "--bind", dest="bind", type=int, help="Bind to port")
        conn_grp.add_argument("-st", "--send_timeout", dest="send_timeout", type=float, default=5.0,
                              help="Set send() timeout (Default 5s)")
        conn_grp.add_argument("-rt", "--recv_timeout", dest="recv_timeout", type=float, default=5.0,
                              help="Set recv() timeout (Default 5s)")
        conn_grp.add_argument("--sleep-time", dest="sleep_time", type=float, default=0.0,
                              help="Sleep time between each test (Default 0)")
        conn_grp.add_argument('-nc', '--new-conns', dest='new_connection_between_requests',
                              help="Open a new connection after each packet of the same test",
                              action='store_true')
        conn_grp.add_argument('-tn', '--transmit_full_path', dest='transmit_full_path',
                              help="Transmit the next node in the graph of the fuzzed node",
                              action='store_true')
        recv_grp = self.parser.add_argument_group('RECV() Options')
        recv_grp.add_argument('-nr', '--no-recv', dest='receive_data_after_each_request',
                              help="Do not recv() in the socket after each send",
                              action='store_false')
        recv_grp.add_argument('-nrf', '--no-recv-fuzz', dest='receive_data_after_fuzz',
                              help="Do not recv() in the socket after sending a fuzzed request",
                              action='store_false')
        recv_grp.add_argument('-cr', '--check-recv', dest='check_data_received_each_request',
                              help="Check that data has been received in recv()",
                              action='store_true')

        crash_grp = self.parser.add_argument_group('Crashes Options')
        crash_grp.add_argument("--threshold-request", dest="crash_threshold_request", type=int, default=9999,
                               help="Set the number of allowed crashes in a Request before skipping it (Default 9999)")
        crash_grp.add_argument("--threshold-element", dest="crash_threshold_element", type=int, default=3,
                               help="Set the number of allowed crashes in a Primitive before skipping it (Default 3)")
        crash_grp.add_argument('--error-fuzz-issues', dest='ignore_connection_issues_after_fuzz',
                               help="Log as error when there is any connection issue in the fuzzed node",
                               action='store_true')

        fuzz_grp = self.parser.add_argument_group('Fuzz Options')
        fuzz_grp.add_argument('--pcap', dest='pcap_filename', type=str, required=True,
                              help='PCAP Seed to build Population from')
        fuzz_grp.add_argument('--prng_seed', dest='prng_seed', type=int, default=0,
                              help='Seed for PRNG to provide reproducibility')

        fuzzers = [fuzzer_class.name for fuzzer_class in IFuzzer.__subclasses__()] + ['raw']

        fuzzers_grp = self.parser.add_argument_group('Fuzzers')
        fuzzers_grp.add_argument("-f", "--fuzz", dest="fuzz_protocol", help='Available Protocols', required=True,
                                 choices=fuzzers)

        restarters_grp = self.parser.add_argument_group('Restart options')
        restarters_help = 'Restarter Modules:\n'
        for restarter in IRestarter.__subclasses__():
            restarters_help += '  {}: {}\n'.format(restarter.name(), restarter.help())
        restarters_grp.add_argument('--restart', nargs='+', default=[], metavar=('module_name', 'args'),
                                    help=restarters_help)
        restarters_grp.add_argument("--restart-sleep", dest="restart_sleep_time", type=int, default=5,
                                    help='Set sleep seconds after a crash before continue (Default 5)')

        monitor_classes = [monitor_class for monitor_class in IMonitor.__subclasses__() if
                           monitor_class != IThreadMonitor]
        monitor_names = [monitor.name() for monitor in monitor_classes]
        monitors_grp = self.parser.add_argument_group('Monitor options')
        monitors_help = 'Monitor Modules:\n'
        for monitor in monitor_classes:
            monitors_help += '  {}: {}\n'.format(monitor.name(), monitor.help())
        monitors_grp.add_argument('--monitors', '-m', nargs='+', default=[],
                                  help=monitors_help, choices=monitor_names)

    def _parse_args(self) -> argparse.Namespace:
        """
        Parse arguments with argparse

        Returns:
            (argparse.Namespace) Argparse arguments
        """
        args = self.parser.parse_args()

        args.fuzz_protocol = [icl for icl in IFuzzer.__subclasses__() if icl.name == args.fuzz_protocol][0]
        args.fuzz_protocol.initialize(**args.__dict__)
        random.seed(args.prng_seed)

        self.restart_module = None
        if len(args.restart) > 0:
            try:
                restart_module = [mod for mod in IRestarter.__subclasses__() if mod.name() == args.restart[0]][0]
                restart_args = args.restart[1:]
                self.restart_module = restart_module(*restart_args)
            except IndexError:
                print(f"The restarter module {args.restart[0]} does not exist!")
                exit(1)

        self.monitors = []
        if len(args.monitors) > 0:
            self.monitors = [mon for mon in IMonitor.__subclasses__() if
                             mon != IThreadMonitor and mon.name() in args.monitors]

        return args

    def run(self):
        """Start the session fuzzer!"""
        self.session.start()


def main():
    epf = EPF()
    # print(REQUESTS)
    # print(blocks.REQUESTS)
    # print(blocks.CURRENT)
    print(logo)
    epf.run()


if __name__ == '__main__':
    main()
