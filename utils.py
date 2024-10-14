import ipaddress
import sys

def validate_timeout(value):
    try:
        timeout = int(value)

        if timeout <= 0:
            print("ERROR\tTimeout must be a positive integer.")
            sys.exit(1)
        
        return timeout

    except ValueError:
        print("ERROR\tTimeout must be a valid integer.")
        sys.exit(1)

def validate_retries(value):
    try:
        retries = int(value)

        if retries <= 0:
            print("ERROR\tNumber of retries must be a positive integer.")
            sys.exit(1)

        return retries

    except ValueError:
        print("ERROR\tNumber of retries must be a valid integer.")
        sys.exit(1)

def validate_port_num(value):
    try:
        port = int(value)

        if port < 0:
            print("ERROR\tPort number cannot be negative.")
            sys.exit(1)
        
        return port

    except ValueError:
        print("ERROR\tPort number must be a valid integer.")
        sys.exit(1)

def validate_server_ipv4(value):
    if not value.startswith('@'):
        print("ERROR\tServer address must start with '@'.")
        sys.exit(1)

    ipv4_str = value[1:]

    try:
        ipaddress.IPv4Address(ipv4_str)
        return ipv4_str
        
    except ipaddress.AddressValueError:
        print("ERROR\tInvalid IPv4 server address.")
        sys.exit(1)