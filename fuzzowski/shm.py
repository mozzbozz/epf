from .constants import INSTR_AFL_MAP_SIZE
from multiprocessing import shared_memory
from .helpers.helpers import get_random_string


class AFLShm(shared_memory.SharedMemory):
    """
    AFLShm is a wrapper for multiprocessing.shared_memory.SharedMemory, which automatically initializes the
    underlying object in such a way that it is compatible to the AFL instrumentation.
    IMPORTANT: Python's new shared_memory Module uses MMAP (shm_open, mmap, ...) , but afl-clang-fast uses the older
    SystemV API (shmget, shmat, ...) by default. You need to compile AFL and afl-clang-fast with -DUSEMMAP in order for
    this to work.
    """
    def __init__(self, identifier: str = None):
        if identifier is None:
            identifier = 'fuzzowski_afl_{}_{}'.format(get_random_string(4), get_random_string(12))
        super().__init__(name=identifier, create=True, size=INSTR_AFL_MAP_SIZE)


__shm = None


def get(identifier: str = None) -> AFLShm:
    """
    Allocate "singleton" linux SHM region which will be passed to instrumented binary.
    Identifier is randomly drawn from /dev/urandom within (MIN_UINT32_T, MAX_UINT32_T) if is None.

    :param identifier: AFLShm.name
    :return: AFLShm
    """
    global __shm
    if __shm is None:
        __shm = AFLShm(identifier=identifier)
    reset()  # not sure if the SharedMemory Object properly initializes the new memory region.
    return __shm


def reset():
    """
    Memset-0 the shared memory
    """
    global __shm
    if __shm is None:
        return
    for i, _ in enumerate(__shm.buf):
        __shm.buf[i] = 0x00
    return


def recreate(identifier: int = None) -> AFLShm:
    """
    Recreate shared memory

    :param identifier: New Identifier, if none, take same identifier as last time
    :return: AFLShm
    """
    global __shm
    tmp = None
    if __shm is not None:
        tmp = __shm.name
        delete()
    return get(identifier=identifier if identifier is not None else tmp)


def delete():
    """
    Delete Shared Memory
    """
    global __shm
    if __shm is not None:
        __shm.close()
        __shm.unlink()
    __shm = None

