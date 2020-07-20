# from typing import Dict, List, Any, Generator
import networkx as nx
import matplotlib.pyplot as plt
from networkx.drawing.nx_agraph import graphviz_layout


class Graph(object):
    def __init__(self):
        self.g = nx.DiGraph()
        self.root = '_root_'
        self.g.add_node(self.root)

    def visualize(self):
        nx.nx_agraph.write_dot(self.g, 'test.dot')

        # same layout using matplotlib with no labels
        pos = graphviz_layout(self.g, prog='dot')
        nx.draw(self.g, pos, with_labels=True, arrows=True)
        # nx.draw(self.g, with_labels=True)
        plt.show()

    def connect(self, src: object, dst=None, callback=None):
        if dst is not None and not self.g.has_node(dst):
            self.g.add_node(dst)
        if not self.g.has_node(src):
            self.g.add_node(src)
        if dst is None:
            dst = src
            src = '_root_'
        if not self.g.has_edge(src, dst):
            self.g.add_edge(src, dst, callback=callback)

    # def fuzzable_iterator(self) -> Generator[Mutant, None, None]:
    #     for mutant in self.g:
    #         if mutant == self.root:
    #             continue
    #         if mutant.fuzzable:
    #             yield mutant

    # def path_to_fuzzable_iterator(self, fuzzable: Mutant):
    #     for n in nx.shortest_path(self.g, source=self.root, target=fuzzable)[1:]:
    #         if n == self.root or n == fuzzable:
    #             continue
    #         yield n
