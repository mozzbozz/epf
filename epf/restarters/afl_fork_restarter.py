import signal
import psutil
import time

from .irestarter import IRestarter
from ..constants import INSTR_AFL_ENV
from .. import shm
import shlex
import os


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
    It's the job of mutants and monitors to further manage such memory.

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
        self._cmd = cmd
        # execve(3) params
        self._argv = shlex.split(self._cmd)
        self._path = self._argv[0]
        self._pid = 0
        self.restarts = 0
        self.crashes = 0

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

    def restart(self, *args, **kwargs) -> str:
        """
        Restarts the target

        :param args: ignored
        :param kwargs: ignored
        :return: information format str
        """
        identifier = shm.get().name  # get instrumentation shared memory id
        environ = _update_env(identifier)  # add pseudorandom shm identifier to environment variable of child process
        cid = self._fork(environ)  # actually fork
        self._pid = cid
        self.restarts += 1
        return f"Forking into AFL-instrumented binary. Command: {self._cmd}, Shared Memory ID: {identifier}, PID: {cid}"

    def kill(self):
        if self._pid != 0:
            try:
                proc = psutil.Process(self._pid)
                for child in proc.children():
                    child.kill()
                proc.kill()
            except Exception:
                pass

    def healthy(self):
        try:
            proc = psutil.Process(self._pid)
            res = proc.status() not in [psutil.STATUS_DEAD, psutil.STATUS_STOPPED]
            if not res:
                self.crashes += 1
                self.kill()
            return res
        except Exception as e:
            pass
        self.crashes += 1
        return False

    def _fork(self, environ: {}) -> int:
        """
        Fork the target via execve

        :param environ: Dictionary representing the environment variables of the child process
        :return: child pid (int)
        """
        cid = os.fork()
        if cid == 0:
            # child
            os.setsid()  # create new session
            os.execve(self._path, self._argv, environ)  # execve into command
            # never returns, see man execve(3)
        # parent
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

