import time
from typing import List, TYPE_CHECKING, Any

from epf.chromo import Individual
from epf.ip_constants import DEFAULT_MAX_RECV
from epf import exception, helpers
from epf import shm

if TYPE_CHECKING:
    from epf.session import Session


class TestCase(object):

    def __init__(self, id: int, session: 'Session', individual: Individual):
        """
        The TestCase contains all the information to perform a test or show information about it.

        Args:
            id: a number (should be the mutation number of the session)
            session: The session file, as most options from the session are used
            individual: The request that is being fuzzed
        """
        self.id = id
        self.session = session
        self.individual = individual

        self.name = f"{self.id}.{self.individual.species.replace(' ', '_')}.{str(self.individual.identity)[-12:]}"
        self.errors = []
        self.coverage_increase = None
        self.needed_restart = False
        self.exit_code = None
        self.individual.testcase = self

    def add_error(self, error):
        """ Add an error to the current case """
        self.errors.append(error)

    def run(self) -> bool:

        """
        Run the test case, transmitting the full path

        Args:
            # fuzz:   (default True) Send the fuzzed node. If it is false, it transmit the original (for tests)
            retry:  (default True) Retry if connection fails

        Returns: True if the TestCase was run and data was transmitted (even if transmission was cut)
                 False if there was a connection issue and the target was paused, so the TestCase was not run
        """
        # target has been run before
        if self.coverage_increase is not None:
            return False
        # assert target is healthy
        complications, retval = self.session.restarter.assert_healthy()
        if complications:
            # previous case crashed target!
            self.session.add_last_case_as_suspect(Exception("process_exit"), complications, retval)
        try:
            self.open_fuzzing_target()
            population = self.session.populations[self.individual.species]
            # process pre-phase of population for state transitions
            for pre in population.state_graph.traverse_pre_phase():
                self.transmit(pre.bytes, receive=pre.recv_after_send)
            # fuzz individual
            self.transmit(self.individual.serialize(), receive=population.recv_after_send)
            # process post-phase of population for state transitions
            for post in population.state_graph.traverse_post_phase():
                self.transmit(post.bytes, receive=post.recv_after_send, relax=self.session.opts.post_relax)
            self.session.target.close()
            coverage_map = shm.get()
            self.coverage_increase = coverage_map.changed
            coverage_map.update_state()
            return True
        except exception.EPFPaused:
            return False  # Returns False when the fuzzer got paused, as it did not run the TestCase
        except exception.EPFTestCaseAborted as e:  # There was a transmission Error, we end the test case
            return True

    def open_fuzzing_target(self):
        """
        Try to open the target, twice in case one fails, saving last case as suspect if something goes wrong,
        restarting the target if a restarter is defined, and waiting for the target to wake up after that.

        """
        target = self.session.target

        try:
            target.open()
        except (exception.EPFTargetConnectionFailedError, Exception):
            try:
                target.open()  # Second try, just in case we have a network error not caused by the fuzzer
            except Exception as e:
                complications, retval = self.session.restarter.assert_healthy(force_kill=True)
                self.session.add_last_case_as_suspect(e, complications, retval)

    def transmit(self, data: bytes, receive=False, relax=False):
        """
        Render and transmit a fuzzed node, process callbacks accordingly.

        Args:
            data: bytes
            receive: if True, it will try to receive data after sending the request

        Returns: None
        Raises: EPFTestCaseAborted when a transmission error occurs
        """

        # 1. SEND DATA
        try:
            self.session.target.send(data)
        except Exception as e:
            if not relax:
                complications, retval = self.session.restarter.assert_healthy(force_kill=True)
                self.session.add_current_case_as_suspect(e, complications, retval)
            return

        # 2. RECEIVE DATA
        if receive:
            try:
                last_recv = self.session.target.recv(DEFAULT_MAX_RECV)
                if not last_recv:
                    raise Exception("empty response after send")
            except Exception as e:
                if not relax:
                    complications, retval = self.session.restarter.assert_healthy(force_kill=True)
                    self.session.add_current_case_as_suspect(e, complications, retval)

    # --------------------------------------------------------------- #

    def print_requests(self):
        """Prints the Requests of this Test Case as python code"""
        # helpers.print_python(self.path)
        print("TODO")

    def print_poc(self):
        """Prints the Test Case as PoC code that can be run standalone"""
        # TODO: Take all options, send the whole test case instead of parameters
        print("TODO")
        # helpers.print_poc(self.session.target, self.path,
        #                   self.session.opts.receive_data_after_each_request, self.session.opts.receive_data_after_fuzz)

    def get_poc(self):
        """Gets the code of the PoC of this Test Case that can be run standalone"""
        # exploit_code = helpers.get_exploit_code(self.session.target, self.path,
        #                                         self.session.opts.receive_data_after_each_request,
        #                                         self.session.opts.receive_data_after_fuzz)
        return "TODO"
        # return exploit_code

    # --------------------------------------------------------------- #

    def __repr__(self):
        return f'{vars(self)}'

    def info(self):
        """Returns information about the test case"""
        return 'TODO'
        # return f'Test Case {self.id} {"(Disabled)" if self.disabled else ""}\n' \
        #        f'  Mutant: {self.mutant_name}\n' \
        #        f'  Errors: {self.errors}'
        # f'  Path: {self.path_name}\n' \
