from .constants import INSTR_AFL_MAP_SIZE, INSTR_AFL_MIN_SHM_ID, INSTR_AFL_MAX_SHM_ID
from multiprocessing import shared_memory
import random
from threading import Lock


class AFLShm(shared_memory.SharedMemory):
    def __init__(self, identifier: int = None):
        if identifier is None:
            identifier = str(random.SystemRandom().randint(INSTR_AFL_MIN_SHM_ID, INSTR_AFL_MAX_SHM_ID))
        super().__init__(name=identifier, create=True, size=INSTR_AFL_MAP_SIZE)

    def __del__(self):
        self.unlink()
        self.close()


__shm = None
__mut = Lock()


def get(identifier: int = None) -> AFLShm:
    """
    Allocate "singleton" linux SHM region which will be passed to instrumented binary.
    Identifier is randomly drawn from /dev/urandom within (MIN_UINT32_T, MAX_UINT32_T) if is None.

    :param identifier: AFLShm.name
    :return: Created shared memory object
    """
    global __mut, __shm
    with __mut:
        if __shm is None:
            __shm = AFLShm(identifier=identifier)
    return __shm


def reset():
    global __mut, __shm
    with __mut:
        if __shm is None:
            return get()
        tmp = __shm
        identifier = tmp.name
        del tmp
        get(identifier)
    return __shm
