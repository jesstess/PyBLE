import struct

def get_packed_bdaddr(bdaddr_string):
    packable_addr = []
    addr = bdaddr_string.split(':')
    addr.reverse()
    for b in addr:
        packable_addr.append(int(b, 16))
    return struct.pack("<BBBBBB", *packable_addr)

def packed_bdaddr_to_string(bdaddr_packed):
    return ':'.join('%02x'%i for i in struct.unpack("<BBBBBB",
                                                    bdaddr_packed[::-1]))

def packet_as_hex_string(pkt):
    packet = ""
    for b in pkt:
        packet = packet + "%02x" % struct.unpack("<B",b)[0]
    return packet

# From the spec, 5.4.1, page 427 (Core Spec v4.0 Vol 2):
# "Each command is assigned a 2 byte Opcode used to uniquely identify different
# types of commands. The Opcode parameter is divided into two fields, called the
# OpCode Group Field (OGF) and OpCode Command Field (OCF). The OGF occupies the
# upper 6 bits of the Opcode, while the OCF occupies the remaining 10 bits"
def ogf_and_ocf_from_opcode(opcode):
    ogf = opcode >> 10
    ocf = opcode & 0x03FF
    return (ogf, ocf)
