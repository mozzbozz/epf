import os
import time

from epf import Target, FuzzLogger, exception
from epf.loggers import FuzzLoggerText
from epf.restarters import IRestarter
from . import helpers
from . import constants
from epf.graph import Graph
from typing import Dict, Any

from .chromo import Population, Individual
from .testcase import TestCase
from epf.prompt.session_prompt import SessionPrompt


class SessionOptions(object):
    """
    This is a dumb, auxiliary class to save all session options
    """

    def __init__(self, *args, **kwargs):
        self.__dict__.update(kwargs)


class SessionClock(object):
    def __init__(self, time_budget: float = 0.0):
        self._budget = time_budget
        self._execution_time = 0.0
        self._start = 0.0
        self._stop = 0.0
        self._running = False

    @property
    def exhausted(self):
        return self._budget > 0 >= self._budget - self._execution_time

    @property
    def execution_time(self):
        return self._execution_time

    @property
    def budget(self):
        return self._budget

    def start(self):
        if self._running:
            return
        self._start = time.time()
        self._running = True

    def stop(self):
        if not self._running:
            return
        self._stop = time.time()
        self._execution_time += self._stop - self._start
        self._running = False


class Session(object):
    """
    Implements main fuzzing functionality, contains all configuration parameters, etc.

    Args:
        restart_sleep_time (float): Time in seconds to sleep when target can't be restarted. Default 5.
        fuzz_loggers (list of ifuzz_logger.IFuzzLogger): For saving test data and results.. Default Log to STDOUT.
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.
        restarter (IRestarter): Restarter module initialized. Will call restart() when the target is down. Default None
        monitors (list of IMonitor): Monitor modules
    """

    def __init__(self,
                 restart_sleep_time: float = 5.0,
                 fuzz_loggers: "list of FuzzLogger" = None,
                 target: Target = None,
                 restarter: IRestarter = None,
                 monitors: "list of IMonitor" = [],
                 seed: int = 0,
                 fuzz_protocol=None,
                 time_budget=0.0
                 ):
        super().__init__()

        self.opts = SessionOptions(
            restart_sleep_time=restart_sleep_time,
            # Transmission Options
            host=target._target_connection.host,
            port=target._target_connection.port,
            send_timeout=target._target_connection._send_timeout,
            recv_timeout=target._target_connection._recv_timeout,
            pcap=fuzz_protocol.pcap_file,
            seed=seed,
            time_budget=time_budget
        )

        # Create Results Dir if it does not exist
        helpers.mkdir_safe(os.path.join(constants.RESULTS_DIR))

        # Make default logger if no others set
        if fuzz_loggers is None:
            fuzz_loggers = [FuzzLoggerText()]

        # Open session file if specified
        # fuzz_loggers.append(FuzzLoggerText(file_handle=open(self.log_filename, 'a')))

        self.logger = FuzzLogger(fuzz_loggers)
        # self.logger = FuzzLogger()
        self.fuzz_protocol = fuzz_protocol

        self.target = target
        if target is not None:
            try:
                self.add_target(target)
            except exception.EPFRpcError as e:  # TODO: Change exception
                self.logger.log_error(str(e))
                raise
        self._requests = []
        self.graph = Graph()

        self.suspects: Dict[int, TestCase or None] = {}  # Dictionary of suspect test cases
        self.latest_tests = []  # List of N test cases
        self.previous_test_possible = False

        self._restarter = restarter

        self.monitors = []
        for monitor_class in monitors:
            self.monitors.append(monitor_class(self))

        # Some variables that will be used during fuzzing
        self.time_budget = SessionClock(time_budget)
        self.test_case_cnt = 0
        self.populations = self.fuzz_protocol.get_populations(self)
        self.population_iterator = iter(sorted(self.populations.keys()))
        self.active_population = self.populations[next(self.population_iterator)]
        self.active_individual = None

        self.is_paused = True
        self.prompt = None

    # ================================================================#
    # Actions                                                         #
    # ================================================================#

    def start(self):
        """
        Starts the prompt once the session is prepared
        """
        self.prompt = SessionPrompt(self)
        self.prompt.start_prompt()

    # --------------------------------------------------------------- #

    def schedule_population(self):
        self.active_population = next(iter(self.populations.items()))[1]

    def generate_individual(self):
        self.active_individual = self.active_population.new_child()

    def evaluate_individual(self):
        # 1. create test case
        self.test_case_cnt += 1
        testcase = TestCase(id=self.test_case_cnt, session=self, individual=self.active_individual)
        # 2. fuzz
        # try:
        testcase.run()
        # except Exception:
        #    pass
        # TODO: 3. evaluate coverage and process feedback
        # self._examine_testcase(...)

    def update_population(self):
        print("TODO UPDATE_POPULATION")
        self.active_population.add(self.active_individual)

    def update_bugs(self):
        print("TODO UPDATE_BUGS")

    def cont(self) -> bool:
        """
        Cont outputs a boolean indicating whether a new fuzz iteration should be processed.

        Currently, this method depends on the time budget and the epf shell pause
        between fuzzing iterations. If the time budget expired or the epf shell has
        been requested, this method returns false.

        Furthermore, cont() is a checkpoint for time budget measurements and updates.
        Each call, the time difference is being calculated.

        @return: bool
        """
        self.time_budget.stop()
        if self.time_budget.exhausted:
            self.logger.log_warn('Time budget exhausted!')
            self.is_paused = True
        result = not (self.time_budget.exhausted or self.is_paused)
        if result:
            self.time_budget.start()
        return result

    def run_all(self):
        while self.cont():                  # while CONTINUE(C) do X
            self.schedule_population()      #   conf <- SCHEDULE(C, t_elapsed, t_limit) <--- -_-
            self.generate_individual()      #   tcs  <- INPUTGEN(conf) <----- NEXT
            self.evaluate_individual()      #   B', execinfos <- INPUTEVAL(conf, tcs, O_bug)
            self.update_population()        #   C <- CONFUPDATE(C', conf, execinfos)
            self.update_bugs()              #   B <- B u B'

            # TODO: When running all test cases and test_interval is set, check if you need to restart the target
            # if self.opts.restart_interval > 0 and self.test_case.id % self.opts.restart_interval == 0:
            #     self.logger.open_test_step(f"Restart interval of {self.opts.restart_interval} reached")
            #     self.restart_target()

    # ================================================================#
    # Graph related functions                                         #
    # =====================================================   ===========#

    def connect(self, src: Any, dst: Any = None, callback: callable = None):
        """
        Connects a request to the session as a root node, or two request between them. Optionally specifying a callback
        in between requests.
        It updates the number of total mutations

        Args:
            src: First request to connect
            dst: Second Request to connect, if None it will connect the src Request as a root node in the session graph
            callback: Optional, specify a callback that will be run in between requests and can change the data
        """
        try:
            self.graph.connect(src, dst, callback)
        except exception.EPFRuntimeError:
            pass

    # ================================================================#
    # Suspects, disabled elements                                     #
    # ================================================================#

    def add_suspect(self, test_case: TestCase):
        """
        Adds a TestCase as a suspect if it was not added previously
        Args:
            test_case: The test case to add as a suspect
        """
        if test_case.id not in self.suspects:
            self.suspects[test_case.id] = test_case
            self.logger.log_info(f'Added test case {test_case.id} as a suspect')

            # Check if crash threshold
            request_crashes = {}
            mutant_crashes = {}
            # TODO: REQUEST WILL HAVE CHANGED WHEN CALLED THIS. FIX
            for suspect in self.suspects.values():
                if suspect is not None:
                    request_name = suspect.request_name
                    request_crashes[request_name] = request_crashes.get(request_name, 0) + 1
                    if request_crashes[request_name] >= self.opts.crash_threshold_request:
                        # Disable request! :o
                        self.logger.log_fail(f'Crash threshold reached for request {request_name}. Disabling it')
                        self.disable_by_path_name(request_name)

                    mutant_name = suspect.mutant_name
                    mutant_crashes[mutant_name] = mutant_crashes.get(mutant_name, 0) + 1
                    if mutant_crashes[mutant_name] >= self.opts.crash_threshold_element:
                        # Disable mutant! :o
                        self.logger.log_fail(f'Crash threshold reached for mutant {request_name}.{mutant_name}. '
                                             f'Disabling it')
                        self.disable_by_path_name(f'{request_name}.{mutant_name}')

    def add_last_case_as_suspect(self, error: Exception):
        """
        Adds the latest test executed as a suspect
        Args:
            error: An Exception to include within the TestCase information
        """
        if len(self.latest_tests) == 0 or self.previous_test_possible is False:
            return  # No latest case to add
        self.logger.log_warn("Adding latest test case as a suspect")
        latest_test = self.latest_tests[0]
        latest_test.add_error(error)
        self.add_suspect(latest_test)
        self.previous_test_possible = False

    def add_latest_test(self, test_case: TestCase):
        pass
        # """ Add a test case to the list of latest test cases keeping the maximum number"""
        # # self.logger.log_info(f"Adding {test_case.id} to latest cases")
        # self.previous_test_possible = True
        # if len(self.latest_tests) == self.opts.tests_number_to_keep:
        #     self.latest_tests.pop()  # Take latest test
        # self.latest_tests.insert(0, test_case)

    def restart_target(self):
        """ It will call the restart() command of the IRestarter instance, if a restarter module was set"""
        if self._restarter is not None:
            try:
                self.logger.open_test_step('Restarting Target')
                restarter_info = self._restarter.restart()
                self.logger.log_info(restarter_info)
            except Exception as e:
                pass
                self.logger.log_fail(
                   "The Restarter module {} threw an exception: {}".format(self._restarter.name(), e))

    def check_monitors(self):
        """ Check all monitors, and add the current test case as a suspect if a monitor returns False """
        for monitor in self.monitors:
            # The monitor run() function decides whether to add a test_case as suspect or not
            monitor.run(self.test_case)

    def add_target(self, target: Target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target: Target to add to session
        """
        target.set_fuzz_data_logger(fuzz_data_logger=self.logger)

        # add target to internal list.
        self.target = target
