import inspect
import subprocess
import time
from typing import Tuple

import psutil

from .irestarter import IRestarter
from ..constants import INSTR_AFL_ENV
from .. import shm
import shlex
import os
import sys


class AFLForkRestarter(IRestarter):
    """
    AFLForkRestarter is a restarter module that implements an execve(3) forkserver that may be
    used in conjunction with AFL-LLVM-instrumented binaries.

    In order for the Instrumentation to properly communicate with Fuzzowski, shared memory is required.
    This technical white paper
        https://github.com/AFLplusplus/AFLplusplus/blob/master/docs/technical_details.md
    explains that the instrumented binary expects to receive a predefined environment variable
    (default: '__AFL_SHM_ID') containing a linux shared memory identifier. Using this input,
    the process attaches to the existing memory and writes information to it.

    Consequently, it is up to the forking parent to allocate, manage and finally free shared memory.
    Due to Fuzzowski's architecture, this module does (at its worst) create shared memory if not already done.

    Note: it does NOT employ the method that has been discussed in
            http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html !
          The intended design in Fuzzowski is not to restart the binary each time it has been
          fed with input. Thus, the resulting overhead that comes with simply forking the target
          is considered to be acceptable.
    """

    def __init__(self, cmd, *args, **kwargs):
        """
        Constructor

        :param cmd: Command including params that will be executed
        :param args: ignored
        :param kwargs: ignored
        """
        # the command to execute
        self.cmd = cmd
        # execve(3) params
        self._argv = shlex.split(self.cmd)
        self._path = self._argv[0]
        self.process = None
        self.restarts = -1
        self.crashes = 0
        self.retval = None

    @staticmethod
    def name() -> str:
        """
        This module's name

        :return: name
        """
        return 'afl_fork'

    @staticmethod
    def help() -> str:
        """
        This module's help

        :return: help str
        """
        return "'<executable> [<argument> ...]' (Pass command and arguments within quotes, as only one argument)"

    def restart(self, *args, **kwargs) -> bool:
        """
        Restarts the target

        :param args: ignored
        :param kwargs: ignored
        :return: bool
        """
        try:
            identifier = shm.get().name  # get instrumentation shared memory id
            environ = _update_env(identifier)  # add pseudorandom shm identifier to environment variable of child process
            cid = self._fork(environ)  # actually fork
            self.process = psutil.Process(cid)
            time.sleep(2.0)
        except Exception as e:
            return False
        self.restarts += 1
        return self.healthy()

    def assert_healthy(self, force_kill=False) -> Tuple[bool, int]:
        while not self.healthy() or force_kill:
            self.kill()
            self.restart()
            force_kill = False
        ret = (False, 0) if self.retval is None else (True, self.retval)
        if self.retval is not None:
            self.crashes += 1
        self.retval = None
        return ret

    def kill(self):
        if self.process is None:
            return
        children = self.process.children()
        for child in children:
            child.terminate()
        _, alive = psutil.wait_procs(children, timeout=1.0)
        for bad_boy in alive:
            bad_boy.kill()
        self.process.terminate()
        _, alive = psutil.wait_procs([self.process], timeout=1.0)
        if len(alive) > 0:
            self.process.kill()
            psutil.wait_procs([self.process], timeout=1.0)
        if self.retval is None:
            self.retval = self.process.returncode
        self.process = None

    def healthy(self) -> bool:
        return self.process is not None and self.process.status() not in [psutil.STATUS_DEAD, psutil.STATUS_STOPPED, psutil.STATUS_ZOMBIE]

    def _fork(self, environ: {}) -> int:
        """
        Fork the target via execve

        :param environ: Dictionary representing the environment variables of the child process
        :return: child pid (int)
        """
        cid = subprocess.Popen(args=self._argv,
                               shell=False,
                               env=environ,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True,
                               close_fds=True).pid
        return cid


def _update_env(identifier: str) -> {}:
    """
    Copy and update parent environment by supplementing AFL instrumentation environment variable

    :param identifier: shared memory identifier
    :return: Updated copy of environment dict
    """
    environ = os.environ.copy()
    environ[INSTR_AFL_ENV] = str(identifier)
    return environ

