from .irestarter import IRestarter
from multiprocessing import shared_memory
import shlex
import os
import random


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
    Due to Fuzzowski's architecture, this module does only allocate and pass shared memory to the target process.
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
        :param args: [0] -> environment variable name, [1] -> int(map_size_pow2) (both optional)
        :param kwargs: ignored
        """

        # AFL instrumentation environment variable (set in #define within AFL)
        self._env_var = "__AFL_SHM_ID" if len(args) < 1 else args[0]
        # Size of SHM to be allocated. Is defined by MAP_SIZE and MAP_SIZE_POW2 in AFL, so we do it as well.
        # Whole SHM should, in a best case scenario, fully fit into higher layer CPU caches. Thus, it defaults to
        # 1 << 16 = 64 Kibibytes! Be aware: smaller map sizes increases the likelihood of collisions within
        # the instrumentation, with falsifies insights
        self._map_size_pow2 = 16 if len(args) < 2 else args[1]
        self._map_size = 1 << self._map_size_pow2
        # int32_t limits. The AFL-instrumented binary expects a str(int32_t) as SHM identifier.
        self._max_shm_id = 0x7FFFFFFF
        self._min_shm_id = -0x80000000
        # the command to execute
        self._cmd = cmd
        # execve(3) params
        self._argv = shlex.split(self._cmd)
        self._path = self._argv[0]

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
        shm = self._create_shm()  # create shm
        environ = self._update_env(shm)  # add pseudorandom shm identifier to environment variable of child process
        cid = self._fork(shm, environ)  # actually fork
        return f"Forking into AFL-instrumented binary. Command: {self._cmd}, Shared Memory ID: {shm.name}, PID: {cid}"

    def _fork(self, shm: shared_memory.SharedMemory, environ: {}) -> int:
        """
        Fork the target via execve, finally pass shared memory to other modules.

        :param shm: Shared memory to extract identifier from
        :param environ: Dictionary representing the environment variables of the child process
        :return: child pid (int)
        """
        cid = os.fork()
        if cid == 0:
            # child
            os.execve(self._path, self._argv, environ)
            # never returns, see man execve(3)
        else:
            # parent
            # TODO: think about how to pass shm, cid and other information I'm currently not aware of to the Session
            pass
        return cid

    def _update_env(self, shm: shared_memory.SharedMemory) -> {}:
        """
        Copy and update parent environment by supplementing AFL instrumentation environment variable

        :param shm: Shared Memory to pass to child
        :return: Updated copy of environment dict
        """
        environ = os.environ.copy()
        environ[self._env_var] = str(shm.name)
        return environ

    def _create_shm(self) -> shared_memory.SharedMemory:
        """
        Allocate linux SHM region which will be passed to instrumented binary.
        Identifier is randomly drawn from /dev/urandom within (MIN_UINT32_T, MAX_UINT32_T).

        :return: Created shared memory object
        """
        identifier = str(random.SystemRandom().randint(self._min_shm_id, self._max_shm_id))
        shm = shared_memory.SharedMemory(name=identifier, create=True, size=self._map_size)
        return shm

