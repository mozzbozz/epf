from typing import Dict, Any, Callable, Union, Tuple

from scapy.fields import Field, PacketListField
from scapy.all import rdpcap
from scapy.packet import Packet
import uuid
from numpy import random, uint64, iinfo
import random as stdrandom
from uuid import UUID


class Chromosome(object):
    def __init__(self, individual: "Individual", field: Field, packet: Packet):
        self._field = field
        self._individual = individual
        self._pkt = packet

    @property
    def name(self):
        return self._field.name

    @property
    def original_value(self) -> Any:
        return self._field.default

    @property
    def current_value(self) -> Any:
        return self._pkt.getfieldval(self._field.name)

    @current_value.setter
    def current_value(self, val: Any):
        self._pkt.setfieldval(self._field.name, val)

    def reset_value(self) -> Any:
        self._pkt.setfieldval(self._field.name, self.original_value)
        return self._field.default

    def random_mutate(self):
        # we can't mutate non-primitives.. randomly choose one within the nested structure and mutate that instead
        field = self._field
        layer = self._pkt
        if isinstance(self._field, PacketListField):
            layer = self._pkt.getlayer(1)
            field = layer.get_field(random.choice(layer.fields_desc).name)
        randval = field.randval()
        if randval is not None:
            layer.setfieldval(field.name, randval._fix())


class Individual(object):
    def __init__(self, packet: Packet, parents: Union[Tuple[UUID, UUID], Tuple[None, None]] = (None, None)):
        self._pkt = packet
        self._chromosomes = self._build_chromosomes()
        self._identifier = uuid.UUID(int=stdrandom.getrandbits(128))
        self._parents = parents
        self.testcase = None
        self.index = -1

    def _mix_genes_on_birth(self, genetics: Dict[str, Chromosome]):
        for name, chromo in genetics.items():
            self._chromosomes[name].current_value = chromo.current_value

    def _build_chromosomes(self) -> Dict[str, Chromosome]:
        chromos = dict()
        for name, field in sorted(self._pkt.fieldtype.items()):
            chromos[name] = (Chromosome(self, field, self._pkt))
        return chromos

    def random_mutation(self):
        keys = sorted(set(self._chromosomes))
        mutation_field = random.choice(keys)
        self._chromosomes[mutation_field].random_mutate()

    def give_birth(self, other_parent: "Individual", genetics: Dict[str, Chromosome]) -> "Individual":
        pkt = self._pkt.copy()
        child = Individual(pkt, parents=(self.identity, other_parent.identity))
        child._mix_genes_on_birth(genetics)
        return child

    @property
    def parents(self) -> Union[Tuple[UUID, UUID], Tuple[None, None]]:
        return self._parents

    @property
    def identity(self):
        return self._identifier

    @property
    def species(self) -> str:
        return self._pkt.name

    @property
    def chromosomes(self) -> Dict[str, Chromosome]:
        return self._chromosomes

    def serialize(self) -> bytes:
        return bytes(self._pkt)

    def compatible(self, other: "Individual") -> bool:
        return all([set(self.chromosomes) == set(other.chromosomes), self.species == other.species])

    def identical(self, other: "Individual") -> bool:
        if not self.compatible(other):
            return False
        chromo_other = other.chromosomes
        return all(v.current_value == chromo_other[k].current_value for k, v in self.chromosomes.items())


class Crossover:

    @staticmethod
    def single_point(a: Dict[str, Chromosome], b: Dict[str, Chromosome]) -> Dict[str, Chromosome]:
        c = {}
        keys = sorted(set(a))
        point = random.randint(0, len(keys))
        for k in keys[:point]:
            c[k] = a[k]
        for k in keys[point:]:
            c[k] = b[k]
        return c


class Population(object):
    def __init__(self,
                 crossover_fn: Callable[[Dict[str, Chromosome], Dict[str, Chromosome]],
                                        Dict[str, Chromosome]] = Crossover.single_point,
                 p_mutation: float = 0.8):
        self._p_mutation = p_mutation
        self._crossover = crossover_fn
        self._pop_by_id = {}
        self._pop = []
        self.crossovers = 0
        self.spot_mutations = 0

    def update(self, child: Individual, heat: float = 1.0, add: bool = False):
        # TODO: CRASHED
        identical = any(o.identical(child) for o in self._pop)
        if identical:
            return
        parents = [self._pop_by_id[pid] for pid in child.parents]
        if child.testcase.coverage_increase:
            # interesting child, prioritize it
            for i, p in enumerate(parents):
                # increase probability of parents to be chosen by moving them up in the order
                new_idx = min(0, p.index - 1)
                if i == 0 and p.index < parents[i + 1].index and new_idx >= parents[i+1].index:
                    parents[i + 1].index -= 1
                self._pop.pop(p.index)
                self._pop.insert(new_idx, p)
            self._pop.insert(0, child)
            self._pop_by_id[child.identity] = child
            return
        for i, p in enumerate(parents):
            # increase probability of parents to be chosen by moving them up in the order
            new_idx = p.index + 1
            if i == 0 and p.index < parents[i + 1].index and new_idx >= parents[i + 1].index:
                parents[i + 1].index -= 1
            self._pop.pop(p.index)
            self._pop.insert(new_idx, p)
        if add:
            # simulated annealing decided to add it either ways...we put the child somewhere based in the heat
            new_idx = int((1 - heat) * len(self._pop))
            self._pop.insert(new_idx, child)
            self._pop_by_id[child.identity] = child

    def shrink(self, size: int):
        if size == 0 or size >= len(self._pop):
            return
        self._pop.pop(len(self._pop) - 1)

    @property
    def species(self):
        return self._pop[0].species if len(self._pop) > 0 else ""

    def add(self, individual: Individual) -> bool:
        same_species = len(self._pop) == 0 or self._pop[0].compatible(individual)
        identical = any(o.identical(individual) for o in self._pop)
        if same_species and not identical:
            self._pop.append(individual)
            self._pop_by_id[individual.identity] = individual
        return same_species

    def new_child(self):
        a_sampler = Population.truncated_uniform_choice
        b_sampler = Population.truncated_uniform_choice
        if random.random() <= 0.5:
            a_sampler = Population.truncated_exp_choice
        else:
            b_sampler = Population.truncated_exp_choice
        a, a_idx = a_sampler(self._pop)
        b, b_idx = (a, a_idx)
        while b == a:
            b, b_idx = b_sampler(self._pop)
        a.index = a_idx
        b.index = b_idx
        # mix chromosomes
        child_chromos = self._crossover(a.chromosomes, b.chromosomes)
        self.crossovers += 1
        # give birth
        c = a.give_birth(b, child_chromos)
        if random.random() <= self._p_mutation:
            self.spot_mutations += 1
            c.random_mutation()
        return c

    def shuffle(self):
        random.shuffle(self._pop)

    def __iter__(self):
        return iter(self._pop)

    def __len__(self) -> int:
        return len(self._pop)

    @staticmethod
    def truncated_exp_choice(pop):
        x = len(pop) + 1
        while x >= len(pop):
            x = random.exponential() * len(pop)
        return pop[int(x)], int(x)

    @staticmethod
    def truncated_uniform_choice(pop):
        x = random.randint(low=0, high=len(pop), dtype=int)
        return pop[x], x


    @staticmethod
    def generate(pcap_filename: str,
                 layer_filter: Callable[[Packet], Union[Packet, None]] = lambda x: x,
                 population_crossover_operator: Callable[[Dict[str, Chromosome], Dict[str, Chromosome]],
                                                         Dict[str, Chromosome]] = Crossover.single_point,
                 population_mutation_probability: float = 0.8,
                 ) -> Dict[str, "Population"]:
        pkts = rdpcap(pcap_filename)
        populations = {}
        for pkt in pkts:
            stripped = layer_filter(pkt)
            if stripped is None:
                continue
            indiv = Individual(stripped)
            if indiv.species not in populations:
                populations[indiv.species] = Population(
                    crossover_fn=population_crossover_operator,
                    p_mutation=population_mutation_probability,
                )
            populations[indiv.species].add(indiv)
        for pop in populations.values():
            pop.shuffle()
        return populations
