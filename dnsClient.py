import argparse
import utils
import struct
from clientSocket import client_socket

def parse_input():
    parser = argparse.ArgumentParser(description="DNS Client")

    # Parse optional arguments
    parser.add_argument("-t", type=utils.validate_timeout, default=5)
    parser.add_argument("-r", type=utils.validate_retries, default=3)
    parser.add_argument("-p", type=utils.validate_port_num, default=53)
    
    # Add mutually exclusive group for -mx/-ns optional flags
    query_type_group = parser.add_mutually_exclusive_group()
    query_type_group.add_argument("-mx", action="store_true")
    query_type_group.add_argument("-ns", action="store_true")

    # Parse required arguments
    parser.add_argument("server", type=utils.validate_server_ipv4)
    parser.add_argument("domain")

    # Init client object
    return parser.parse_args()

def parse_response(response):
    # RESPONSE HEADER
    ID = int.from_bytes(response[:2], byteorder='big')
    FLAGS = int.from_bytes(response[2:4], byteorder='big')
    QDCOUNT = int.from_bytes(response[4:6], byteorder='big')
    ANCOUNT = int.from_bytes(response[6:8], byteorder='big')
    NSCOUNT = int.from_bytes(response[8:10], byteorder='big')
    ARCOUNT = int.from_bytes(response[10:12], byteorder='big')

    if ANCOUNT > 0:
        print(f"*** Answer Section ({ANCOUNT} records) ***")

        # ANSWER SECTION
        offset = 12
        # Skip QNAME section
        while response[offset] != 0:
            offset += 1
        # Skip 0x00 label, QTYPE, and QCLASS
        offset += 5
            
        for i in range(ANCOUNT):
            length = response[offset]
            # First 2 bits are '11' indicate that it is a pointer
            if length & 0xC0 == 0xC0:
                offset += 2
            else:
                # Skip NAME
                while response[offset] != 0:
                    offset += 1
                # Skip 0x00 label
                offset += 1
            
            # Extract TYPE
            TYPE = int.from_bytes(response[offset:offset + 2], byteorder='big')
            offset += 2
            CLASS = int.from_bytes(response[offset:offset + 2], byteorder='big')
            offset += 2
            TTL = int.from_bytes(response[offset: offset + 4], byteorder='big')
            offset += 4
            RDLENGTH = int.from_bytes(response[offset: offset + 2], byteorder='big')
            offset += 2

            # Mask every bit except AA in FLAGS for [auth | nonauth]
            AUTH = "auth" if FLAGS & 0x0400 == 1 else "nonauth"

            if TYPE == 0x0001:
                # Build RDATA which is IP address in this case
                labels = []
                pointer = offset

                for i in range(4):
                    label = str(int.from_bytes(response[pointer:pointer + 2], 'big'))
                    pointer += 2
                    labels.append(label)

                RDATA = ".".join(labels)

                print(f"IP\t{RDATA}\t{TTL}\t{AUTH}")
            elif TYPE == 0x0002:
                print("NS")
            elif TYPE == 0x005:
                RDATA = response[offset:offset + RDLENGTH]
                labels = []
                ix = 0

                while ix < RDLENGTH:
                    length = RDATA[ix]

                    # Pointer if first 2 bits are '11'
                    if length & 0xC0 == 0xC0:
                        # Get pointer offset by masking first 2 bits
                        pointer = struct.unpack_from(">H", RDATA, ix)[0] & 0x3FFF 
                        ix += 2

                        while response[pointer] != 0:
                            label_len = response[pointer]
                            pointer += 1
                            label = ""

                            for i in range(pointer, pointer + label_len):
                                label += chr(response[i])
                            
                            labels.append(label)
                            pointer += label_len
                    # Otherwise, parse alias label
                    else:
                        # Skip byte indicating label length as we have already stored value in length var
                        ix += 1
                        label = ""

                        for i in range(ix, ix + length):
                            label += chr(RDATA[i])

                        labels.append(label)
                        ix += length



                ALIAS = ".".join(labels)

                print(f"CNAME\t{ALIAS}\t{TTL}\t{AUTH}")
            elif TYPE == 0x000f:
                print("MX")
            else:
                print("Error?")

            # Increment offset by RDLENGTH
            offset += RDLENGTH

def main():
    args = parse_input()
    
    # Default query type is A
    query_type = "A"

    if args.mx:
        query_type = "MX"
    elif args.ns:
        query_type = "NS"

    # Init DNS client socket
    socket = client_socket(args.t, args.r, args.p, query_type, args.server, args.domain)
    # Send DNS query
    response = socket.query()
    # Parse DNS response
    parse_response(response)
    

if __name__ == "__main__":
    # Type A Query: python3 dnsClient.py -t 10 -r 3 @8.8.8.8 www.mcgill.ca
    # Type MX Query: python3 dnsClient.py -t 10 -r 2 -mx @8.8.8.8 mcgill.ca
    main()