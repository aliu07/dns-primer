import socket
import struct
import random
import time

class ClientSocket:
    query_type_dict = {'A': 0x0001, 'MX': 0x000f, 'NS': 0x0002}

    def __init__(self, timeout, max_retries, port_num, query_type, server_ip, domain_name):
        self.timeout = timeout
        self.max_retries = max_retries
        self.port_num = port_num
        self.query_type = query_type
        self.server_ip = server_ip
        self.domain_name = domain_name

    def build_dns_query(self):
        ## HEADER SECTION

        # Generate random ID between 0x0000 and 0xFFFF
        ID = random.randint(0, 65535)
        # Query flags: QR = 0, Opcode = 0000, AA = 0, TC = 0, RD = 1, RA = 0, Z = 000, RCODE = 0000 -> 0x0100
        FLAGS = 0x0100
        # 1 entry in question section always
        QDCOUNT = 1
        # Answer, authority, and additional record counts = 0 for query
        ANCOUNT = 0
        NSCOUNT = 0
        ARCOUNT = 0
        # Construct header in binary format
        # '>' - Specifies bieg-endian byte order
        # 'H' - Specifies unsigned short (16-bit value i.e. 2 bytes). We have 6 entires of 16 bits, so 6 H's.
        header = struct.pack(">HHHHHH", ID, FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

        ## DNS QUESTION SECTION

        # Init QNAME to empty byte string
        QNAME = b''
        # Build QNAME
        for label in self.domain_name.split("."):
            # 'B' - Specifies a singular byte (8 bits)
            QNAME += struct.pack(">B", len(label))
            # Encode each label and append to QNAME
            QNAME += label.encode('ascii')
        
        # Append 0-length label to mark end of QNAME field
        QNAME += b'\x00'
        # Fetch corresponding query type
        QTYPE = self.query_type_dict[self.query_type]
        # Class of query always 0x0001 for Internet address
        QCLASS = 0x0001

        question = QNAME + struct.pack(">HH", QTYPE, QCLASS)
        
        # BUILDING DNS QUERY
        return ID, header + question


    def query(self):
        # Save start timestamp
        start = time.time()

        # Init DNS query packet
        packet_id, packet = self.build_dns_query()

        # Init UDP socket
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_socket.settimeout(self.timeout)

        # Print to stdout
        print(f"DnsClient sending request for {self.domain_name}")
        print(f"Server: {self.server_ip}")
        print(f"Request type: {self.query_type}")

        num_attempts = 0

        while num_attempts < self.max_retries:
            try:
                client_socket.sendto(packet, (self.server_ip, self.port_num))
                response, _ = client_socket.recvfrom(512)

                # Save end timestamp
                end = time.time()
                print(f"Response received after {end - start} seconds ({num_attempts} retries)")
                return packet_id, response
            except socket.timeout:
                print(f"Timeout on attempt {num_attempts + 1}.{' Retrying...' if num_attempts < self.max_retries - 1 else ''}")
                num_attempts += 1

        # If still no response after max number of retries
        print(f"ERROR\tMaximum number of retries {self.max_retries} exceeded")
        return None, None