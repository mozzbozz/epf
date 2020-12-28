# EPF - Evolutionary Protocol Fuzzer

<div style="text-align: center;">
<img src="https://i.imgur.com/fLfssJY.png" alt="status" style="width:75%;"/>
</div>

<div style="text-align: center;">
<img src="https://i.imgur.com/M4TPuTt.png" alt="system overview" style="width:75%;"/>
</div>

**EPF** is a coverage guided protocol-aware network fuzzer.
It combines [Scapy](https://github.com/secdev/scapy) packet models with
prebuilt state transition graphs to increase process depth and, 
[thus](https://mboehme.github.io/paper/IEEESoftware20.pdf), bug finding
effectiveness during dynamic analysis.
Static instrumentation - borrowed from
[AFL](https://lcamtuf.coredump.cx/afl/) and
[AFL++](https://github.com/AFLplusplus/AFLplusplus)
([USENIX](https://www.usenix.org/conference/woot20/presentation/fioraldi)) -
is used to establish a dynamic feedback loop that is fed into a
population-based simulated annealing algorithm.
The fuzzer aims to maximize test coverage metrics on the target
by incrementally evolving and mutating a population of valid sample packets.
Such *seeds* are obtained by feeding EPF with PCAP files.

In other words, you teach EPF a target protocol, pass a compile-time instrumented
target network binary, and provide PCAP examples of well-defined communication.
EPF then tries to maximize fuzzing effectiveness by automatically setting the
network target into reasonable processing states. Genetic algorithms derive new -
partially corrupt - packets with the goal to trigger undefined behavior and security
policy violations during dynamic analysis.

***Disclaimer: EPF is the result of my master's thesis and has been developed under the
influence of LOTS of coffee, sleep deprivation, and was further constrained by a tight
timetable. During development, I fell into every pitfall that comes with writing a
complex fuzzer - ranging from non-determinism over problematic bug oracles to missing
synchronization with the target application.***


## Contents

1. [**About the Thesis**](#documentation%2Fconcept%2Fdevelopment%2Fthesis)
2. [**Why does EPF exist?**](#why%3F)
3. [**Dependencies**](#dependencies)
4. [**Setup**](#setup)
5. [**Synopsis**](#synopsis)
6. [**Example**](#example)
7. [**Contributions**](#contributions)

## Documentation/Concept/Development/Thesis

*Note: Currently unpublished. However, feel free to contact me for a copy if you are interested.*

```plain
R. Helmke. "Smarter Grid Fuzzing: Effective Greybox Fuzzing for Power Grid Communication Protocols". Master's Thesis. Osnabrück, Germany: Department of Computer Science, University of Osnabrück, Nov. 2020.
```

This thesis was supervised by the
[Distributed Systems Group](https://sys.cs.uos.de) of the University of Osnabrück and the
[Cyber Analysis & Defense Group](https://www.fkie.fraunhofer.de/en/departments/cad.html)
of the Fraunhofer FKIE, Bonn.


## Why?
**Network fuzzing frameworks like [Boofuzz](https://github.com/jtpereyda/boofuzz) are
great**. They lower the entry barrier to network fuzzing
by abstracting every annoying fuzzer aspect that is not
directly related to the target: Boilerplate code is reduced,
convenience wrappers exist, and there is a core engine for
input mutation and crash detection as well.
If you are missing bits and pieces for your particular scenario,
APIs enable you to add them by yourself.

**Network protocol implementations are
[very challenging to fuzz](https://mboehme.github.io/paper/IEEESoftware20.pdf)**
because each protocol has its own set of states and requires highly
structured input (packet types!).
Also, complex sequences of bidirectional communication dictate the flow of execution.
Think about it this way: you can't just throw a network server at
[AFL](https://lcamtuf.coredump.cx/afl/) and expect the fuzzer to somehow know how
to interact with the target.
AFL's main domain, that is fuzzing commandline applications with file capabilities,
is way more simple:
your ordinary `objdump` target expects some kind of filepath or bytestream as input.
It is either passed via `Environment` variables, `arguments`, or using `stdin`.
`objdump` receives the fuzzer's input, processes it, and terminates *(or crashes)*.

Without protocol awareness, a fuzzer fails to generate input that is valid to the
target. For example, a network server may only process a packet type when
certain conditions are met or particular states are active.
Otherwise, the packet or even connection is immediately dropped due to protocol
violations. Then, most of the code base remains unexecuted.
Dynamic analysis can not test code when its not executed.
Thus, **a network fuzzer must be able to reach *process depth* by
controlling and manipulating the target's protocol state through well-defined
communication**.

Most scientific work in the domain of network fuzzing picks a protocol and
contributes general communication capabilities (grammar/models) to existing blackbox
frameworks, e.g., [Boofuzz](https://github.com/jtpereyda/boofuzz).
While this is a reasonable - if not mandatory - approach to reach process depth,
**few work tries to push boundaries to further increase effectiveness**.
However, these boundaries may not always be as heavy as assumed by the network community.
In recent years, there were tremendous advances in the broader scientific fields
of fuzzing, dynamic- and static-analysis, and combinatorial optimization.
**By introducing novel techniques and algorithms, fuzzing effectiveness can be
increased by several magnitudes above the state of the art**.
Manès et al. provide an excellent
[survey](https://softsec.kaist.ac.kr/~sangkilc/papers/manes-tse19.pdf) of the current state of the art in fuzzing.
[Böhme](https://mboehme.github.io/) et al.
[discuss](https://mboehme.github.io/paper/IEEESoftware20.pdf) present and
future challenges in fuzzing.

The **applicability of such novel techniques is bound to certain assumptions that
must be true during the fuzzing scenario**.
E.g., all work that is consolidated by
[Fioraldi et al.](https://www.usenix.org/conference/woot20/presentation/fioraldi) is
built on top of the coverage-guided [AFL](https://lcamtuf.coredump.cx/afl/) fuzzer.
AFL requires the presence of source code (not always, but is beneficial) and a
working target build toolchain. The resulting executable must be runnable
in the fuzzer's own execution environment.

Sticking to the requirements and benefits of AFL, **coverage-guidance is a technique
that establishes a feedback loop between the program under test and the fuzzer to
heuristically estimate and improve the performance and effectiveness of input
generation**:
During compilation, we add static instrumentation that sends coverage metrics
to the fuzzer when dynamic analysis runs.
Fuzzing is then formulated as maximization problem. A coverage-guided fuzzer is
a heuristic solver that aims to maximize the test coverage by intelligently mutating
input in such a way that, at best, all parts of the program under test were executed.

Except for [AFLNet](https://github.com/aflnet/aflnet), which was published during
the making of EPF and shares many conceptual similarities, **there is no publicly
available network fuzzer that assumes the previously mentioned assumptions to be
true**. Simply put, the whole domain of network fuzzing misses out on tremendous
achievements in performance optimization.
Undeniably, not all network target
source code can be downloaded, preprocessed, and put on your own computer.
However, if possible, why shouldn't you be able to clone a network server's source code from github,
instrument it, and execute it on your own machine? Bind it to
`localhost` and lets go.

This is where EPF comes into play: **under the assumption that the required
constraints for coverage-guided fuzzing are fulfilled, EPF aims to transfer the
state of the art of fuzzing to the network domain. By doing so, the effectiveness of
finding bugs shall be increased**.

Thus, **EPF is the second coverage-guided network fuzzer
(thanks AFLNet;-) and the first evolutionary network fuzzer that is available to
the public.**
Based on the main topic of its corresponding thesis, it was prototypically developed
for the domain of power grid communication protocols, but is not limited to it.
*Why should it be? You have to provide a state graph for each protocol either ways :-/.* 

## Dependencies

**System:**

```bash
sudo apt-get update && sudo apt get install python3 python3-pip python3-venv
```

*Additionally:* [AFL++](https://github.com/AFLplusplus/AFLplusplus) for compile-time instrumentation.

**Python:**

```plain
prompt-toolkit
attrs
pygments
pydot
sysv_ipc
posix_ipc
networkx
scapy
matplotlib
npyscreen
hexdump
numpy
psutil
cryptography
```

## Setup

1. install [AFL++](https://github.com/AFLplusplus/AFLplusplus) by following the
project's [build instructions](https://github.com/AFLplusplus/AFLplusplus#building-and-installing-afl).
2. install EPF:
```bash
git clone https://github.com/rhelmke/epf.git # clone
cd epf                                       # workdir
python3 -m venv .env                         # setup venv
source .env/bin/activate                     # activate venv
pip3 install -r requirements.txt             # dependencies
```

You should now have a working copy of both AFL++ and EPF. Verify the latter with:
```bash
python3 -m epf --help
```
EPF must always be executed within the previously setup virtual python environment.

## Synopsis

```plain
$ python3 -m epf --help

`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"`-:-.   ,-;"
   `=`,'=/     `=`,'=/     `=`,'=/     `=`,'=/
     y==/        y==/        y==/        y==/
   ,=,-<=`.    ,=,-<=`.    ,=,-<=`.    ,=,-<=`.
,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_,-'-'   `-=_
        - Evolutionary Protocol Fuzzer -

positional arguments:
  host                  target host
  port                  target port

optional arguments:
  -h, --help            show this help message and exit

Connection options:
  -p {tcp,udp,tcp+tls}, --protocol {tcp,udp,tcp+tls}
                        transport protocol
  -st SEND_TIMEOUT, --send_timeout SEND_TIMEOUT
                        send() timeout
  -rt RECV_TIMEOUT, --recv_timeout RECV_TIMEOUT
                        recv() timeout

Fuzzer options:
  --fuzzer {iec104}     application layer fuzzer
  --debug               enable debug.csv
  --batch               non-interactive, very quiet mode
  --dtrace              extremely verbose debug tracing
  --pcap PCAP           pcap population seed
  --seed SEED           prng seed
  --alpha ALPHA         simulated annealing cooldown parameter
  --beta BETA           simulated annealing reheat parameter
  --smut SMUT           spot mutation probability
  --plimit PLIMIT       population limit
  --budget TIME_BUDGET  time budget
  --output OUTPUT       output dir
  --shm_id SHM_ID       custom shared memory id overwrite
  --dump_shm            dump shm after run

Restart options:
  --restart module_name [args ...]
    Restarter Modules:
        afl_fork: '<executable> [<argument> ...]' (Pass command and arguments within quotes, as only one argument)
  --restart-sleep RESTART_SLEEP_TIME
                        Set sleep seconds after a crash before continue (Default 5)
```

## Example

To provide a working example on how to prepare and use EPF with your target protocol,
we are going to fuzz [lib60870](https://github.com/mz-automation/lib60870) by
MZ Automation. It is an open source implementation of the IEC 60870-5-101/104
SCADA protocols. They are commonly used in european critical power infrastructure
for remote monitoring and controlling.
The main reason of why this target has been chosen is of simple nature: the master's
thesis that EPF originates from focuses on this domain.

### Example Step 1: Download, Instrument, and Build the Target

*We assume that epf, aflplusplus, and lib60870 are all situated in the user's home.*

**Download**

```bash
git clone https://github.com/mz-automation/lib60870.git
cd lib60870/lib60870-C
```

**Prepare Instrumentation**

We need to exchange the C compiler with the AFL++ toolchain to instrument the code during
compilation. It is nothing but a wrapper for `clang`:

```bash
# may vary, check how your target project selects the compiler. most of the time, a CC=... environment variable is sufficient
echo "CC=~/AFLplusplus/afl-clang-fast" >> make/target_system.mk
```

**Compile**

```bash
make
```

You have now a working, instrumented, and statically linked library of
lib60870 that is compatible with both EPF and AFL++ (`./build/lib60870.a`).

**Test Harness**

You can not run lib60870 on its own because it is a library. This is why we need a
**test harness**, a minimal executable wrapper around the library that allows the
fuzzer to pass input to the target. In this case, we only need a wrapper that
initializes the library and creates a socket. The `cs104_server_no_threads` example
in the target's project folder
(`lib60870-C/examples/cs104_server_no_threads/cs104_server_no_threads.c`) is sufficient.
It is a minimal IEC 60870-5-104 slave server application.

Because the `Makefile` in this folder does adhere to `make/target_system.mk`,
we can simply compile the executable:

```bash
cd examples/cs104_server_no_threads
make
cp cs104_server_no_threads ~
```

The resulting `cs104_server_no_threads` executable is the input for EPF. Take note that
it has been copied to `~`.

### Step 2: Teach EPF the protocol

*Everything but the last paragraph is skippable if you only want to execute this example*

Each target protocol requires its own module in EPF's project structure.
Modules come in this subfolder:

```bash
cd ~/epf/epf/fuzzers
```

Take `iec104` as an example:

```python
$ cat iec104/iec104.py

from typing import Union, Dict

from epf.fuzzers.ifuzzer import IFuzzer
from epf import Session, constants
from epf.transition_payload import TransitionPayload
from epf.chromo import Population, Crossover
from scapy.contrib.scada.iec104 import IEC104_APDU_CLASSES
from scapy.packet import Packet


class IEC104(IFuzzer):
    name = 'iec104'
    pcap_file = ''
    populations = {}

    @staticmethod
    def layer_filter(pkt: Packet) -> Union[Packet, None]:
        """
        Filter to extract iec 104 apdu packets only.
        @param pkt: Packet to strip a specific layer from
        @return: Stripped Layer or None if completely discard
        """
        if not any(layer in pkt for layer in IEC104_APDU_CLASSES.values()):
            return None
        return pkt.getlayer(3)

    @staticmethod
    def get_populations(session: Session) -> Dict[str, Population]:
        return IEC104.populations

    # --------------------------------------------------------------- #

    @staticmethod
    def initialize(*args, **kwargs) -> None:
        IEC104.pcap_file = kwargs['pcap']
        IEC104.populations = Population.generate(
            pcap_filename=IEC104.pcap_file,
            layer_filter=IEC104.layer_filter,
            population_crossover_operator=Crossover.single_point,
            population_mutation_probability=constants.SPOT_MUT,
        )
        testfr = TransitionPayload(name="testfr", payload=b'\x68\x04\x43\x00\x00\x00', recv_after_send=True)#True)
        startdt = TransitionPayload(name="startdt", payload=b'\x68\x04\x07\x00\x00\x00', recv_after_send=True)#True)
        stopdt = TransitionPayload(name="stopdt", payload=b'\x68\x04\x13\x00\x00\x00', recv_after_send=False)
        # <-- in case we want to receive after sending an individual of a specific population
        for species, pop in IEC104.populations.items():
            if species == 'population_that_requires_receive':
                pop.recv_after_send = True
            if species != 'IEC-104 U APDU':
                pop.state_graph.pre(testfr)
                pop.state_graph.pre(startdt)
                pop.state_graph.finalize_pre()
                pop.state_graph.post(stopdt)
                pop.state_graph.finalize_post()
            else:
                pop.state_graph.finalize_pre()
                pop.state_graph.finalize_post()
```

Each protocol in EPF requires a layer filter, which uses scapy data models to filter
the relevant packets from PCAP files for dynamic analysis (`layer_filter(...)`).
Because iec104 is already supported by PCAP, we do not have to implement the models.

The `initialize` method is called by the fuzzer to kick off pcap parsing. Another
important aspect is the minimal state graph that is constructed for the purpose of
fuzzing IEC 60870-5-104.
You can define so-called `TransitionPayload(s)` which can be concatenated in a
directed acyclic graph. These are sent before (`pre`) fuzzing a specific packet type and
afterward (`post`). This enables EPF to connect to the target, open a session, and trigger
state transitions for proper packet handling. The code depicted above constructs
the following acyclic graph for the protocol-specific I- S-, and U-Packet Types:

<div style="text-align: center;">
<img src="https://i.imgur.com/mZpF0fu.png" alt="iec104 state graph" style="width:75%;"/>
</div>

That's it. If you follow this layout based on the iec104 module as example for your
own protocol, you are now done.

**Except for one small thing**: For our IEC 60870-5-104 example, we must apply a
data type patch to scapy's iec104 implementation because there is (in my opinion)
a bug in the sequence number field representation. Apply
the `01_scapy_iec104_sequence_number_fix.patch` which has been shipped as part
of the EPF project. It is in `~/epf/patches`.

### Example Step 3: Fuzz the target!

**Acquire a pcap file containing legitimate communication between the target and a
client**

... [here](https://github.com/automayt/ICS-pcap/raw/master/IEC%2060870/iec104/iec104.pcap)'s one for IEC 60870-5-104, for example. We call it `iec104.pcap` from now on.
You put it in `~/epf`.

**Run epf!**

... but don't forget to `cp ~/cs104_server_no_threads ~/epf` into EPF's project dir ;).

```bash
cd ~/epf
source .env/bin/activate  # activate virtualenv
python -m epf 127.0.0.1 2404 -p tcp --fuzzer iec104 --pcap iec104.pcap --seed 123456 --restart afl_fork "./cs104_server_no_threads" --smut 0.2 --plimit 1000 --alpha 0.99999333 --beta 1.0 --budget 86400
```

*Hint: Refer to [**Synopsis**](#synopsis) for the meaning of each argument.*

You'll be greeted with an interactive console, which is a stripped down version
of EPF's base project, [Fuzzowski](https://github.com/nccgroup/fuzzowski):

<div style="text-align: center;">
<img src="https://i.imgur.com/1fvx50G.png" alt="console" style="width:75%;"/>
</div>

Type `continue` to start fuzzing. This is the status screen:


<div style="text-align: center;">
<img src="https://i.imgur.com/fLfssJY.png" alt="status" style="width:75%;"/>
</div>

Press `ctrl+q` to return to the console. Type `exit` to exit EPF.

Results are in `~/epf/epf-results`. However, they require manual verification
due to a high false positive rate: A bug that was introduced during the thesis
had to be hotfixed by flushing the history of previous

## Contributions

I'm actively looking for people that are willing to contribute their fuzzing- and
development-expertise to this project. The goal is to completely rewrite EPF's PoC
implementation in a more stable/structured/robust/effective/modular way.
The language of choice is Rust.
