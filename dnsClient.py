import argparse
import utils
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

def main():
    args = parse_input()
    
    # Default query type is A
    query_flag = "A"

    if args.mx:
        query_flag = "MX"
    elif args.ns:
        query_flag = "NS"

    # Init DNS client socket
    socket = client_socket(args.t, args.r, args.p, query_flag, args.server, args.domain)
    response = socket.query()
    print(response)

if __name__ == "__main__":
    # Query: python3 dnsClient.py -t 10 -r 3 -p 34 -mx @8.8.8.8 www.mcgill.ca
    main()