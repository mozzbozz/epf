import csv
import json
import os
import time
from numpy import random

from epf import Target, exception
from epf.restarters import IRestarter
from . import helpers
from . import shm
from . import constants
from epf.graph import Graph
from typing import Dict, Any

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
        target (Target):        Target for fuzz session. Target must be fully initialized. Default None.
        restarter (IRestarter): Restarter module initialized. Will call restart() when the target is down. Default None
    """

    def __init__(self,
                 restart_sleep_time: float = 5.0,
                 target: Target = None,
                 restarter: IRestarter = None,
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


        self.fuzz_protocol = fuzz_protocol

        self.target = target
        if target is not None:
            try:
                self.add_target(target)
            except exception.EPFRpcError as e:  # TODO: Change exception
                raise
        self._requests = []
        self.graph = Graph()

        self.suspects = []

        self.restarter = restarter

        # Some variables that will be used during fuzzing
        self.time_budget = SessionClock(time_budget)
        self.test_case_cnt = 0
        self.populations = self.fuzz_protocol.get_populations(self)
        self.population_iterator = iter(sorted(self.populations.keys()))
        self.active_population = self.populations[next(self.population_iterator)]
        self.drain_seed_iterator = iter(self.active_population)
        self.active_individual = None
        self.active_testcase = None
        self.previous_testcase = None
        self.drain_seed_individuals = False

        self.is_paused = False
        self.prompt = None
        self.energy = 1.0
        self.energy_hist = []
        self.energy_threshold = 0.05
        self.energy_periods = 0
        self.reheat_count = 0

        # Create Results Dir if it does not exist
        self.result_dir = os.path.join('epf-results', f'{int(time.time())}')
        self.transition_payload_dir = os.path.join(self.result_dir, 'transition_payloads')
        helpers.mkdir_safe(self.result_dir)
        helpers.mkdir_safe(self.transition_payload_dir)
        self.write_run_json()
        for p in iter(sorted(self.populations.keys())):
            helpers.mkdir_safe(os.path.join(self.transition_payload_dir, p))
        # TODO: self.write_transition_payloads()
        self.bugs_csv = None
        self.bugs_csv_writer = None
        self.prepare_bugs_csv()

    def write_run_json(self):
        json_file = os.path.join(self.result_dir, "run.json")
        mem = shm.get()
        data = {
            "general": {
                "fuzzer": self.fuzz_protocol.name,
                "time_budget": self.time_budget.budget,
                "random_seed": self.opts.seed,
            },
            "target": {
                "exec_command": self.restarter.cmd,
                "protocol": self.target.target_connection.proto,
                "connection": f'{self.target.target_connection.host}:{self.target.target_connection.port}',
                "send_timeout": self.opts.send_timeout,
                "recv_timeout": self.opts.recv_timeout,
            },
            "instrumentation": {
                "mmap_id": mem.name,
                "injection_env": constants.INSTR_AFL_ENV,
                "mem_size": mem.size / 1024,
            },
            "genetics": {
                "populations": {
                    "seed": self.opts.pcap,
                    "count": len(self.populations),
                    "population_names": [p for p in iter(sorted(self.populations.keys()))],
                    "population_sizes": [len(self.populations[p]) for p in iter(sorted(self.populations.keys()))],
                    "population_limit": self.opts.population_limit,
                },
                "simulated_annealing": {
                    "cooldown_alpha": self.opts.alpha,
                    "reheat_beta": self.opts.beta,
                    "spot_mutation_probability": self.active_population._p_mutation,
                },
            },
        }
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

    def prepare_bugs_csv(self):
        b_file = os.path.join(self.result_dir, 'bugs.csv')
        self.bugs_csv = open(b_file, "w")
        header = [1,"2",3]
        self.bugs_csv_writer = csv.DictWriter(self.bugs_csv, fieldnames=header)
        self.bugs_csv_writer.writeheader()
        self.bugs_csv.flush()
        #writer.writerow({'first_name': 'Baked', 'last_name': 'Beans'})
        #writer.writerow({'first_name': 'Lovely', 'last_name': 'Spam'})
        #writer.writerow({'first_name': 'Wonderful', 'last_name': 'Spam'})


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
        self.previous_testcase = self.active_testcase
        self.active_testcase = TestCase(id=self.test_case_cnt, session=self, individual=self.active_individual)
        self.active_testcase.run()

    def update_population(self):
        increase = self.active_testcase.coverage_increase
        if self.active_testcase.coverage_increase:
            self.reheat()
            self.active_population.update(self.active_individual, heat=self.energy, add=increase)
        self.active_population.update(self.active_individual, heat=self.energy, add=random.random() <= self.energy)
        self.active_population.shrink(self.opts.population_limit)

    def update_bugs(self):
        # TODO: CSV
        pass

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

    def add_current_case_as_suspect(self, error: Exception, complications: bool, exit_code: int):
        self.add_suspect(self.active_testcase, error, complications, exit_code)

    def add_last_case_as_suspect(self, error: Exception, complications: bool, exit_code: int):
        if self.previous_testcase is None:
            return
        self.add_suspect(self.previous_testcase, error, complications, exit_code)

    def add_suspect(self, testcase: TestCase, error: Exception, complications: bool, exit_code: int):
        testcase.add_error(error)
        testcase.needed_restart = complications
        testcase.exit_code = exit_code
        self.suspects += [testcase]

    def add_target(self, target: Target):
        """
        Add a target to the session. Multiple targets can be added for parallel fuzzing.

        Args:
            target: Target to add to session
        """

        # add target to internal list.
        self.target = target
