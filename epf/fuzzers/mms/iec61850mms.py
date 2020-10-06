import sys
from typing import Union, Dict

from epf.fuzzers.ifuzzer import IFuzzer
from epf import Session
from epf.transition_payload import TransitionPayload
from epf.chromo import Population, Crossover
from .iec61850_mms_scapy import iec61850_mms
from .iec61850_mms_scapy.iec61850_mms.mms.packets import MMS_Read_Request, MMS_Write_Request
from scapy.packet import Packet


class IEC61850_MMS(IFuzzer):
    name = 'mms'
    pcap_file = ''
    populations = {}

    _extraction_layers = {
        "MMS_Initiate_Request_PDU": [
            iec61850_mms.ISO_8823_Presentation_CP_Type,
            iec61850_mms.AARQ,
            iec61850_mms.MMS_Initiate_Request_PDU
        ],
        "MMS_Confirmed_Request_PDU": [
            iec61850_mms.ISO_8823_Presentation_CPC_Type,
            iec61850_mms.MMS_Confirmed_Request_PDU
        ]
    }

    @staticmethod
    def layer_filter(pkt: Packet) -> Union[Packet, None]:
        """
        Filter to extract iec 104 apdu packets only.
        @param pkt: Packet to strip a specific layer from
        @return: Stripped Layer or None if completely discard
        """
        init = IEC61850_MMS._traverse_to_layer(pkt, IEC61850_MMS._extraction_layers["MMS_Initiate_Request_PDU"])
        if init is not None:
            return init
        return IEC61850_MMS._traverse_to_layer(pkt, IEC61850_MMS._extraction_layers["MMS_Confirmed_Request_PDU"])

    @staticmethod
    def _traverse_to_layer(pkt, layers=[]):
        tmp = pkt
        try:
            for cls in layers:
                tmp = tmp[cls]
        except IndexError:
            tmp = None
        return tmp

    @staticmethod
    def get_populations(session: Session) -> Dict[str, Population]:
        return IEC61850_MMS.populations

    @staticmethod
    def population_identifier(pkt) -> str:
        if MMS_Write_Request in pkt:
            return f"{pkt.name} - Write"
        if MMS_Read_Request in pkt:
            return f"{pkt.name} - Read"
        return pkt.name

    @staticmethod
    def initialize(*args, **kwargs) -> None:
        iec61850_mms.bind_layers()
        IEC61850_MMS.pcap_file = kwargs['pcap']
        IEC61850_MMS.populations = Population.generate(
            pcap_filename=IEC61850_MMS.pcap_file,
            layer_filter=IEC61850_MMS.layer_filter,
            population_identifier=IEC61850_MMS.population_identifier,
            population_crossover_operator=Crossover.single_point,
            population_mutation_probability=0.8,
        )
        for pop in IEC61850_MMS.populations.values():
            pop.state_graph.finalize_pre()
            pop.state_graph.finalize_post()
            #pop._pop[0].random_mutation()
            #print(pop._pop[0].serialize())
            #pop._pop[0]._pkt.show2()
        # testfr = TransitionPayload(name="testfr", payload=b'\x68\x04\x43\x00\x00\x00', recv_after_send=True)
        # startdt = TransitionPayload(name="startdt", payload=b'\x68\x04\x07\x00\x00\x00', recv_after_send=True)
        # stopdt = TransitionPayload(name="stopdt", payload=b'\x68\x04\x13\x00\x00\x00', recv_after_send=False)
        # # <-- in case we want to receive after sending an individual of a specific population
        # for species, pop in IEC104.populations.items():
        #     if species == 'population_that_requires_receive':
        #         pop.recv_after_send = True
        #     if species != 'IEC-104 U APDU':
        #         pop.state_graph.pre(testfr)
        #         pop.state_graph.pre(startdt)
        #         pop.state_graph.finalize_pre()
        #         pop.state_graph.post(stopdt)
        #         pop.state_graph.finalize_post()
        #     else:
        #         pop.state_graph.finalize_pre()
        #         pop.state_graph.finalize_post()

