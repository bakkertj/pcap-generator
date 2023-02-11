
# Default source address to 192.168.1.1
source      = 0xc0a80101

# Default destination address to 192.168.1.2
destination = 0xc0a80102

# Default port to 1973 
port = 1973

#Custom Foo Protocol Packet
message =  ('')   


"""----------------------------------------------------------------"""
""" Do not edit below this line unless you know what you are doing """
"""----------------------------------------------------------------"""

import sys
import binascii
import json
import socket

# Opening JSON file
with open('config.json') as json_file:
    data = json.load(json_file)

if data['packet']['config']['ip']['port'] :
    port = data['packet']['config']['ip']['port']

if data['packet']['config']['ip']['source'] :
    source = data['packet']['config']['ip']['source']

if data['packet']['config']['ip']['destination'] :
    destination = data['packet']['config']['ip']['destination']

if data['packet']['id'] :
    id = data['packet']['id']

with open('example.json') as dictionary_json_file:
    packet_dictionary = json.load(dictionary_json_file)

#Global header for pcap 2.4
pcap_global_header =   ('D4 C3 B2 A1'   
                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00 00 00 00'     
                        '00 00 00 00'     
                        'FF FF 00 00'     
                        '01 00 00 00')

#pcap packet header that must preface every packet
pcap_packet_header =   ('AA 77 9F 47'     
                        '90 A2 04 00'     
                        'XX XX XX XX'   #Frame Size (little endian) 
                        'YY YY YY YY')  #Frame Size (little endian)

eth_header =   ('00 00 00 00 00 00'     #Source Mac    
                '00 00 00 00 00 00'     #Dest Mac  
                '08 00')                #Protocol (0x0800 = IP)

ip_header =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                   
                '40 00 40'                
                '11'                    #Protocol (0x11 = UDP)          
                'YY YY'                 #Checksum - will be calculated and replaced later      
                'S1 S2 S3 S4'           #Source IP (Default: 192.168.1.1)         
                'D1 D2 D3 D4')          #Dest IP (Default: 192.168.1.2) 

udp_header =   ('80 01'                   
                'XX XX'                 #Port - will be replaced later                   
                'YY YY'                 #Length - will be calculated and replaced later        
                '00 00')
                
def getByteLength(str1):
    return int(len(''.join(str1.split())) / 2 )

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()  
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'wb')
    bitout.write(bytes)

def packHex( element ):
    return 'DEAD'

def packInteger( element ):
    return 'DEAD'
    
def packString( element ):
    return 'DEAD'
    
functions = {
    'Integer': packInteger,
    'String':  packString,
    'Hex':     packHex
}

def generatePCAPFileHeader(pcapfile): 

    bytestring = pcap_global_header 
    writeByteStringToFile(bytestring, pcapfile)

def generateExamplePacket( id, pcapfile ):

    global ip_header
    global message


    source_hex = str(binascii.hexlify(socket.inet_aton(str(source))))
    ip_header = ip_header.replace('S1', str(source_hex[2:4] ))
    ip_header = ip_header.replace('S2', str(source_hex[4:6] ))
    ip_header = ip_header.replace('S3', str(source_hex[6:8] ))
    ip_header = ip_header.replace('S4', str(source_hex[8:10]))
  
    destination_hex = str(binascii.hexlify(socket.inet_aton(str(destination))))
  
    ip_header = ip_header.replace('D1', str(destination_hex[2:4] ))
    ip_header = ip_header.replace('D2', str(destination_hex[4:6] ))
    ip_header = ip_header.replace('D3', str(destination_hex[6:8] ))
    ip_header = ip_header.replace('D4', str(destination_hex[8:10]))




    for v in packet_dictionary['messages']:
        if id == v['id']:
            for k in v['data_element']:
                print(k['length'])
                print(k['name'])
                print(k['type']['format'])
                # determine if type is int and call appropriate data type
                func = functions[k['type']['format']]
                message += func(k)
    print(message)

    udp = udp_header.replace('XX XX',"%04x"%port)
    udp_len = getByteLength(message) + getByteLength(udp_header)
    udp = udp.replace('YY YY',"%04x"%udp_len)

    ip_len = udp_len + getByteLength(ip_header)
    ip = ip_header.replace('XX XX',"%04x"%ip_len)

    checksum = ip_checksum(ip.replace('YY YY','00 00'))
    ip = ip.replace('YY YY',"%04x"%checksum)

    pcap_len = ip_len + getByteLength(eth_header)
    hex_str = "%08x"%pcap_len
    reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
    pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
    pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

    bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message
    writeByteStringToFile(bytestring, pcapfile)

#Splits the string into a list of tokens every n characters
def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes    
    words = splitN(''.join(iph.split()),4)

    csum = 0;
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""

if len(sys.argv) < 2:
        print ('usage: pcapgen.py output_file')
        exit(0)

generatePCAPFileHeader( sys.argv[1] )
generateExamplePacket( 2430, sys.argv[1])
