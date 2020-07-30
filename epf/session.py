import os
import time
from numpy import random

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
                 fuzz_protocol: "IFuzzer" = None,
                 alpha: float = 0.0,
                 beta: float = 0.0,
                 population_limit: int = 10000,
                 time_budget: float = 0.0
                 ):
        super().__init__()

        self.opts = SessionOptions(
            restart_sleep_time=restart_sleep_time,
            # Transmission Options
            host=target.target_connection.host,
            port=target.target_connection.port,
            send_timeout=target.target_connection._send_timeout,
            recv_timeout=target.target_connection._recv_timeout,
            pcap=fuzz_protocol.pcap_file,
            seed=seed,
            alpha=alpha,
            beta=beta,
            population_limit=population_limit,
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
        self.drain_seed_iterator = iter(self.active_population)
        self.active_individual = None
        self.active_testcase = None
        self.drain_seed_individuals = False

        self.is_paused = False
        self.prompt = None
        self.energy = 1.0
        self.energy_hist = []
        self.energy_threshold = 0.05
        self.energy_periods = 0
        self.reheat_count = 0
        self._restarter.restart()

    # ================================================================#
    # Actions                                                         #
    # ================================================================#

    def cooldown(self) -> float:
        self.energy *= self.opts.alpha
        return self.energy

    def reheat(self) -> float:
        self.reheat_count += 1
        self.energy = min(1.0, self.energy / self.opts.beta)
        return self.energy

    def start(self):
        """
        Starts the prompt once the session is prepared
        """
        self.prompt = SessionPrompt(self)
        self.prompt.start_prompt()

    # --------------------------------------------------------------- #

    def schedule_population(self):
        if self.energy <= self.energy_threshold:
            key = next(self.population_iterator, None)
            if key is None:
                # reset
                self.population_iterator = iter(sorted(self.populations.keys()))
                self.energy_periods += 1
                key = next(self.population_iterator)
            self.active_population = self.populations[key]
            self.energy = 1.0
        self.cooldown()

    def generate_individual(self):
        self.active_individual = self.active_population.new_child()

    def evaluate_individual(self):
        # 1. create test case
        self.test_case_cnt += 1
        self.active_testcase = TestCase(id=self.test_case_cnt, session=self, individual=self.active_individual)
        # 2. fuzz
        # try:
        self.active_testcase.run()
        # time.sleep(2.0)
        if self.active_testcase.crashed:
            # TODO: CRASH HANDLING
            self._restarter.restart()

    def update_population(self):
        increase = self.active_testcase.coverage_increase
        if self.active_testcase.coverage_increase:
            self.reheat()
            self.active_population.update(self.active_individual, heat=self.energy, add=increase)
        self.active_population.update(self.active_individual, heat=self.energy, add=random.random() <= self.energy)
        self.active_population.shrink(self.opts.population_limit)

    def update_bugs(self):
        pass
        # print("TODO UPDATE_BUGS")

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
        self.energy_hist += [self.energy]
        return result

    def drain(self):
        while not self.is_paused:
            self.active_individual = next(self.drain_seed_iterator, None)
            if self.active_individual is None:
                key = next(self.population_iterator, None)
                if key is None:
                    # reset
                    self.population_iterator = iter(sorted(self.populations.keys()))
                    self.drain_seed_individuals = False
                    return
                self.active_population = self.populations[key]
                self.drain_seed_iterator = iter(self.active_population)
                continue
            _ = self.active_testcase.coverage_increase
            self.evaluate_individual()
            self.update_bugs()

    def run_all(self):
        if self.drain_seed_individuals:
            self.drain()
        while self.cont():                  # while CONTINUE(C) do X
            self.schedule_population()      #   conf <- SCHEDULE(C, t_elapsed, t_limit) <--- X
            self.generate_individual()      #   tcs  <- INPUTGEN(conf) <----- NEXT
            self.evaluate_individual()      #   B', execinfos <- INPUTEVAL(conf, tcs, O_bug)
            self.update_population()        #   C <- CONFUPDATE(C', conf, execinfos)
            self.update_bugs()              #   B <- B u B'

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
        return
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
