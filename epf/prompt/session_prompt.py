import os
import sys
import signal
from typing import TYPE_CHECKING
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles

from epf import constants
from epf import exception

from .prompt import CommandPrompt

if TYPE_CHECKING:
    from epf.session import Session


class SessionPrompt(CommandPrompt):

    def __init__(self, session: 'Session'):
        super().__init__()
        self.session: 'Session' = session
        signal.signal(signal.SIGINT, self._signal_handler)

    # ================================================================#
    # CommandPrompt Overridden Functions                              #
    # ================================================================#

    def get_commands(self):
        """ Contains the full list of commands"""
        commands = super().get_commands()
        commands.update({
            'info': {
                'desc': 'Show Session Information',
                'exec': self._cmd_info,
            },
            # 'print': {
            #     'desc': 'Print a test case by index',
            #     'exec': self._cmd_print_test_case
            # },
            'poc': {
                'desc': 'Print the python poc code of test case by index',
                'exec': self._cmd_print_poc_test_case
            },
            'performance': {
                'desc': 'Performance',
                'exec': self._cmd_performance,
            },
            'suspects': {
                'desc': 'print information about the tests suspected of crashing something',
                'exec': self._cmd_suspects
            },
            'suspects-del': {
                'desc': 'delete suspect',
                'exec': self._cmd_delsuspect
            },
            'restart': {
                'desc': 'Launch the restarter module to restart the target',
                'exec': self._cmd_restart
            },
            'graph': {
                'desc': 'graph',
                'exec': self._cmd_graph
            },

        })
        return commands

    # --------------------------------------------------------------- #

    def get_prompt(self):
        host = self.session.target.target_connection.host
        port = str(self.session.target.target_connection.port)

        return HTML('[<testn>#</testn>] '
                    '<b>➜</b> <host>{}</host>:<port>{}</port> $ '
                    .format(host, port))

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        elapsed = round(self.session.time_budget.execution_time, 2)
        budget = round(self.session.time_budget.budget, 2)
        toolbar_message = HTML(f'<bttestn>{self.session.fuzz_protocol.name}</bttestn> <b>&gt;</b> '
                               f'Iterations: <bttestn>{self.session.test_case_cnt}</bttestn>'
                               f'| ExecTime (s): <bttestn>{elapsed}</bttestn>/<bttestn>{budget}</bttestn> '
                               f'| PSeed: <bttestn>{self.session.fuzz_protocol.pcap_file}</bttestn> '
                               f'| PRNG: <bttestn>{self.session.opts.seed}</bttestn> '
                               f'| Active Pop.: <bttestn>{self.session.active_population.species}</bttestn> ')
        return toolbar_message

    # --------------------------------------------------------------- #

    def handle_break(self, tokens: list) -> bool:
        if tokens[0] in ('c', 'continue'):
            self.session.is_paused = False
            self.session.run_all()
            return True
        else:
            return False

    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                sys.exit(0)

    # --------------------------------------------------------------- #

    def _signal_handler(self, _signal, frame):
        self.session.is_paused = True
        try:
            print_formatted_text(HTML(' <testn>SIGINT received. Pausing fuzzing after this test case...</testn>'),
                                 style=self.get_style())
        except RuntimeError:
            # prints are not safe in signal handlers.
            # This happens if the signal is catch while printing
            pass

    # --------------------------------------------------------------- #

    def _print_color(self, color, message):
        print_formatted_text(HTML(f'<{color}>{message}</{color}>'),
                             style=self.get_style())

    # --------------------------------------------------------------- #

    def _print_error(self, message):
        self._print_color('red', message)

    # ================================================================#
    # Command handlers                                                #
    # ================================================================#

    def _cmd_info(self, _):
        self._print_color('gold', 'Session Options:')
        for k, v in self.session.opts.__dict__.items():
            print(f'  {str(k)} = {str(v)}')

        self._print_color('gold', '\nPopulations:')
        for k, v in self.session.populations.items():
            fstr = f'  Population = \'{k}\', Individuals = {len(v)}'
            if v == self.session.active_population:
                self._print_color("green", fstr)
            else:
                print(fstr)

    def _cmd_performance(self, _):
        self._print_color('gold', 'Session Options:')
        for k, v in self.session.opts.__dict__.items():
            print(f'  {str(k)} = {str(v)}')

        self._print_color('gold', '\nPopulations:')
        for k, v in self.session.populations.items():
            fstr = f'  Population = \'{k}\', Individuals = {len(v)}'
            if v == self.session.active_population:
                self._print_color("green", fstr)
            else:
                print(fstr)

    def _cmd_print_test_case(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError:  # No index specified, print actual case
            if self.session.test_case is not None:
                self.session.test_case.print_requests()
            return
        except ValueError:
            self._print_error('print usage: print [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            self.session.test_case.print_requests()
        self.session.load_session_state(session_state)

    def _cmd_print_poc_test_case(self, tokens):
        try:
            test_case_index = int(tokens[0])
        except IndexError: # No index specified, print actual case
            if self.session.test_case is not None:
                self.session.test_case.print_poc()
            return
        except ValueError:
            self._print_error('poc usage: poc [TEST_ID]')
            return
        session_state = self.session.save_session_state()
        self.session.goto(test_case_index)
        if self.session.test_case is not None:
            self.session.test_case.print_poc()
        self.session.load_session_state(session_state)

    # --------------------------------------------------------------- #

    def _cmd_suspects(self, tokens):
        try:
            test_case_index = int(tokens[0])
            suspect = self.session.suspects[test_case_index]
            print(suspect.info())
        except IndexError:  # No index specified, Show all suspects
            for suspect_id, suspect in self.session.suspects.items():
                if suspect is not None:
                    print(suspect.info())
                else:
                    print(f'Test Case {suspect_id}')
            return
        except ValueError:
            self._print_error('suspects usage: suspects [TEST_ID]')
            return
        except KeyError:
            self._print_error(f'Suspect with id {tokens[0]} not found')

    def _cmd_delsuspect(self, tokens):
        try:
            test_case_index = int(tokens[0])
            suspect = self.session.suspects.pop(test_case_index)
            print(f'Removing {suspect} from suspects')
        except IndexError:  # No index specified, Show all suspects
            self._print_error('delsuspect usage: delsuspect TEST_ID')
            return
        except ValueError:
            self._print_error('delsuspect usage: delsuspect TEST_ID')
            return
        except KeyError:
            self._print_error(f'Suspect with id {tokens[0]} not found')

    # --------------------------------------------------------------- #

    def _cmd_restart(self, _):
        """
        Launch the restarter module of the session, if a restarter module was set
        """
        self.session.restart_target()

    # --------------------------------------------------------------- #

    def get_style(self):
        return merge_styles([super().get_style(), Style.from_dict(constants.STYLE)])

    # --------------------------------------------------------------- #

    def intro_message(self):
        print_formatted_text(HTML('Fuzzing paused! Welcome to the <b>EPF Shell</b>'))

    # --------------------------------------------------------------- #

    def exit_message(self):
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))

    # --------------------------------------------------------------- #

    def _cmd_graph(self, tokens):
        self.session.graph.visualize()
