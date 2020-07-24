from typing import Dict, Any, Callable, Union, Tuple

from scapy.fields import Field, PacketListField
from scapy.all import rdpcap
from scapy.packet import Packet
import uuid
import random
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
        self._identifier = uuid.UUID(int=random.getrandbits(128))
        self._parents = parents
        self._fitness = 0  # TODO: FITNESS

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

    @property
    def fitness(self) -> int:
        # TODO: FITNESS
        return sum(self.serialize())

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
        a = random.choice(self._pop)
        b = random.choice(self._pop)
        while b == a:
            b = random.choice(self._pop)
        # mix chromosomes
        child_chromos = self._crossover(a.chromosomes, b.chromosomes)
        # give birth
        c = a.give_birth(b, child_chromos)
        if random.random() <= self._p_mutation:
            c.random_mutation()
        return c

    def __iter__(self):
        return iter(self._pop)

    def __len__(self) -> int:
        return len(self._pop)

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
        return populations
