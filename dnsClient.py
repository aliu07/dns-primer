import argparse
import utils
from clientSocket import clientSocket

class dnsClient:
    def parse_input(self):
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

    # Not meant as constructor, meant as init function for sending/receiving a DNS query
    def init(self):
        args = self.parse_input()
        # Default query type is A
        query_type = "A"

        if args.mx:
            query_type = "MX"
        elif args.ns:
            query_type = "NS"

        # Init DNS client socket
        socket = clientSocket(args.t, args.r, args.p, query_type, args.server, args.domain)
        # Send DNS query
        response = socket.query()
        # Parse DNS response
        self.parse_response(response)
    
    def parse_response(self, response):
        if response == None:
            return

        # RESPONSE HEADER
        ID = int.from_bytes(response[:2], byteorder='big')
        FLAGS = int.from_bytes(response[2:4], byteorder='big')
        QDCOUNT = int.from_bytes(response[4:6], byteorder='big')
        ANCOUNT = int.from_bytes(response[6:8], byteorder='big')
        NSCOUNT = int.from_bytes(response[8:10], byteorder='big')
        ARCOUNT = int.from_bytes(response[10:12], byteorder='big')
        # Mask every bit except AA in FLAGS for [auth | nonauth]
        AUTH = "auth" if FLAGS & 0x0400 == 1 else "nonauth"

        if ANCOUNT == 0:
            print("NOTFOUND")
        elif ANCOUNT < 0:
            print("ERROR\tUnexpected response: record count is negative.")
        else:
            print(f"*** Answer Section ({ANCOUNT} records) ***")
            # Init offset to 12 to skip header
            offset = 12
            # Skip QNAME section
            while response[offset] != 0:
                offset += 1
            # Skip 0x00 label, QTYPE, and QCLASS
            offset += 5
                
            # Extracting all answer section records
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
                
                # RESPONSE ANSWER SECTION
                TYPE = int.from_bytes(response[offset:offset + 2], byteorder='big')
                offset += 2
                CLASS = int.from_bytes(response[offset:offset + 2], byteorder='big')
                offset += 2
                TTL = int.from_bytes(response[offset: offset + 4], byteorder='big')
                offset += 4
                RDLENGTH = int.from_bytes(response[offset: offset + 2], byteorder='big')
                offset += 2

                if TYPE == 0x0001:
                    # If we do not have 4 octets, we do not have a valid IP address
                    if RDLENGTH != 4:
                        print("ERROR\tInvalid IP address field in answer record.")
                        continue
                    # Build IP address
                    IP_ADDRESS = ".".join(str(label) for label in response[offset:offset + 4])
                    print(f"IP\t{IP_ADDRESS}\t{TTL}\t{AUTH}")

                elif TYPE == 0x0002:
                    ALIAS = self.parse_alias(response, offset)
                    print(f"NS\t{ALIAS}\t{TTL}\t{AUTH}")

                elif TYPE == 0x005:
                    ALIAS = self.parse_alias(response, offset)
                    print(f"CNAME\t{ALIAS}\t{TTL}\t{AUTH}")

                elif TYPE == 0x000f:
                    PREFERENCE = int.from_bytes(response[offset:offset + 2], byteorder='big')
                    ALIAS = self.parse_alias(response, offset + 2)
                    print(f"MX\t{ALIAS}\t{PREFERENCE}\t{TTL}\t{AUTH}")

                else:
                    print(f"ERROR\tUnsupported record type found in answer section: {TYPE}.")

                offset += RDLENGTH

        if ARCOUNT > 0:
            print(f"*** Additional Section ({ARCOUNT} records) ***")

    def parse_alias(self, response, offset):
        labels = []

        while True:
            length = response[offset]

            # Base case: Hit 0x00 terminating byte
            if length == 0:
                offset += 1
                break

            # Case: Encounter a compressed pointer
            elif length & 0xC0 == 0xC0:
                # Mask first 2 bits of pointer's first byte
                # Shift up 8 bits to make space for 2 byte of pointer
                # Bitwise OR with 2nd byte to get full offset
                pointer = ((length & 0x3F) << 8) | response[offset + 1]
                labels.append(self.parse_alias(response, pointer))
                offset += 2
                break
            
            # Case: Encounter a label we have to decode
            else:
                labels.append(response[offset+1:offset+1+length].decode())
                offset += length + 1

        return ".".join(labels)



if __name__ == "__main__":
    # Type A Query: python3 dnsClient.py -t 10 -r 3 @8.8.8.8 www.mcgill.ca
    # Type MX Query: python3 dnsClient.py -t 10 -r 2 -mx @8.8.8.8 mcgill.ca
    # Type NS Query: python3 dnsClient.py -ns @8.8.8.8 mcgill.ca
    # python3 dnsClient.py -mx @8.8.8.8 gmail.com
    dnsClient = dnsClient()
    dnsClient.init()