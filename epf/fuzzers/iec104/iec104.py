from typing import Union, Dict

from epf.fuzzers.ifuzzer import IFuzzer
from epf import Session
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
            population_mutation_probability=0.8,
        )
#        # ESTABLISH CONNECTION NOFUZZ
#        s_initialize("connect_nofuzz")
#        s_static(b'\x68\x04\x07\x00\x00\x00')
#
#        s_initialize("disconnect_nofuzz")
#        s_static(b'\x68\x04\x07\x00\x00\x00')
#        s_initialize("iec104_sframe")
#        with s_block("iec104_apci"):
#            s_byte(0x68, name='APCI_START', fuzzable=False)
#            s_byte(0x00, name="APCI_LENGTH", fuzzable=True)  # LATER
#            s_byte(0b00000011, name="APCI_OCTET1", fuzzable=False)  # LATER
#            s_byte(0b00000000, name="APCI_OCTET2", fuzzable=True)
#            s_byte(0b00000000, name="APCI_OCTET3", fuzzable=True)
#            s_byte(0b00000000, name="APCI_OCTET4", fuzzable=True)


#     @staticmethod
#     def sframe(session: Session) -> None:
#         pass
#         # session.connect(s_get('connect_nofuzz'))
#         # session.connect(s_get('connect_nofuzz'), s_get('iec104_sframe'))
