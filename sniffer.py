from socket import *
import struct
import sys
import re
import binascii

# Recibimos los datagramas
def RecepData(s):
    data = ''
    try:
        data = s.recvfrom(2048)
    except timeout:
        data = ''
    except:
        print ("Ocurrio un error: ")
        sys.exc_info()
    return data[0]

def get_mac_addr(mac_raw):
    byte_str = map('{:02x}'.format, mac_raw)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr

def ObtenerflagsTCP(packet):
    Flag_URG = {0: "|-Urgent flag    :   0", 1: "|-Urgent flag    :   1"}
    Flag_ACK = {0: "|-Acknowledgement Flag   :  0", 1: "|-Acknowledgement Flag   :  1"}
    Flag_PSH = {0: "|-Push flag  :   0", 1: "|-Push flag  :   1"}
    Flag_RST = {0: "|-Reset flag     :    0", 1: "|-Reset flag     :    1"}
    Flag_SYN = {0: "|-Synchronize flag   :  0", 1: "|-Synchronize flag   :  1"}
    Flag_FIN = {0: "|-Finish Flag    :   0", 1: "|-Finish Flag    :   1"}

    URG = packet & 0x020
    URG >>= 5
    ACK = packet & 0x010
    ACK >>= 4
    PSH = packet & 0x008
    PSH >>= 3
    RST = packet & 0x004
    RST >>= 2
    SYN = packet & 0x002
    SYN >>= 1
    FIN = packet & 0x001
    FIN >>= 0

    tabs = '\n'
    Flags = Flag_URG[URG] + tabs + Flag_ACK[ACK] + tabs+ Flag_PSH[PSH] + tabs + Flag_RST[RST] + tabs + \
            Flag_SYN[SYN] + tabs + Flag_FIN[FIN]
    return Flags


# Obtemnemos el Type of Service (TOS): 8 bits

# Obtenermos los Flags: 3 bits

# Obtenemos el protocolo: 8 bits

while True:


    # la interfaz de red pública
    HOST = gethostbyname(gethostname())
     #creamos un socket sin procesar y vincularlo a la interfaz pública
    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    s.bind((HOST, 0))

    # Incluye encabezados IP
    s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    # Modo promiscuo habilitado
    s.ioctl(SIO_RCVALL, RCVALL_ON)


    #Recibimos los datos
    data = RecepData(s)


# Unpack ethernet frame



    eth_length = 14

    eth_header = data[:eth_length]
    eth = struct.unpack('!6s6sH' , eth_header)
    dest_mac = get_mac_addr(data[0:6])
    src_mac = get_mac_addr(data[6:12])
    proto = eth[2]

    print('JUAN GUILLERMO LAURA MAMANI CI:8301405')
    print()
    print('ETHERNET HEADER')
    print('|-Destination Address :'+ dest_mac)
    print('|-Source address      :'+ src_mac)
    print('|-Protocol            :'+ str(proto))

    # Parse IP packets, IP Protocol number = 8

    # obtener el encabezado IP (los primeros 20 bytes) y descomprimirlos
    # B - carácter sin signo (1)
    # H - corto sin signo (2)
    # s - cadena
    unpackedData = struct.unpack('!BBHHHBBH4s4s' , data[:20])
    version_IHL = unpackedData[0]
    version = version_IHL >> 4                  # Version IP
    IHL = version_IHL & 0xF                     # longitud del encabezado
    TOS = unpackedData[1]                       # type of service
    totalLength = unpackedData[2]
    ID = unpackedData[3]                        # ID
    flags = unpackedData[4]
    fragmentOffset = unpackedData[4] & 0x1FFF
    TTL = unpackedData[5]                       # TTL
    protocolNr = unpackedData[6]
    checksum = unpackedData[7]
    sourceAddress = inet_ntoa(unpackedData[8])
    destinationAddress = inet_ntoa(unpackedData[9])
    print()
    print('IP HEADER')
    print('|-IP Version        :'+str(version))
    print('|-IP Header Length  :'+str(IHL)+' WORDS or '+str(IHL*4) + " bytes")
    print('|-Type Of Service   :'+str(TOS))
    print('|-IP Total Length   :'+ str(totalLength)+ 'Bytes(Size of Packet')
    print('|-Identification    :'+str(ID))
    print('|-TTL      :'+str(TTL))
    print('|-Protocol :'+str(protocolNr))
    print('|-Checksum :'+ str(checksum))
    print('|-Source IP        :'+ sourceAddress)
    print('|-Destination IP   : ' +destinationAddress)

    if protocolNr == 6 :
        print()
        print('TCP HEADER')
        tcp_header = data[IHL*4+14:IHL*4 + 34]

        # now unpack them :)
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        source_port = tcph[0]  # uint16_t
        dest_port = tcph[1]  # uint16_t
        sequence = tcph[2]  # uint32_t
        acknowledgement = tcph[3]  # uint32_t
        doff_reserved = tcph[4]  # uint8_t
        tcph_length = doff_reserved >> 4

        tcph_flags = tcph[5]  # uint8_t
        tcph_window_size = tcph[6]  # uint16_t
        tcph_checksum = tcph[7]  # uint16_t
        tcph_urgent_pointer = tcph[8]  # uint16_t
        print("|-Source Port:", source_port)
        print("|-Destination Port:", dest_port)
        print("|-Sequence Number:", sequence)
        print("|-Acknowledge Number:", acknowledgement)
        print("|-Header Length:", tcph_length, 'DWORDS or ', str(tcph_length * 32 // 8), 'bytes')
        print(ObtenerflagsTCP(tcph_flags))
        print("|-Window Size:", tcph_window_size)
        print("|-Checksum:", tcph_checksum)
        print("|-Urgent Pointer:", tcph_urgent_pointer)
        print("")

        h_size = IHL*4 + tcph_length * 4
        data_size = len(data) - h_size

        # get data from the packet
        data2 = data[h_size:]
        print(data2)

    if protocolNr == 1:
        print()
        print('ICMP HEADER')
        u = IHL*4 + eth_length
        icmph_length = 4
        icmp_header = data[u:u + 4]

        # now unpack them :)
        icmph=struct.unpack('!BBH', icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]

        print('|-Type : ' + str(icmp_type))
        print('|-Code : ' + str(code) )
        print('|-Checksum : ' + str(checksum))

        h_size = eth_length + IHL+4 + icmph_length
        data_size = len(data) - h_size

        # get data from the packet

    if protocolNr == 17:
        print()
        print('UDP HEADER')
        u = IHL+4 + eth_length
        udph_length = 8
        udp_header = data[u:u + 8]

        # now unpack them :)
        udph=struct.unpack('!HHHH', udp_header)
        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]

        print('|-Source Port : ' + str(source_port) )
        print('|-Dest Port : ' + str(dest_port) )
        print('|-Length : ' + str(length) )
        print('|-Checksum : ' + str(checksum))

        h_size = eth_length + IHL+4 + udph_length
        data_size = len(data) - h_size

    s.ioctl(SIO_RCVALL, RCVALL_OFF)