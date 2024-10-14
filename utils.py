import ipaddress

def validate_timeout(value):
    try:
        timeout = int(value)

        if timeout <= 0:
            raise argparse.ArgumentTypeError("ERROR\tTimeout must be a positive integer.")
        
        return timeout

    except ValueError:
        raise argparse.ArgumentTypeError("ERROR\tTimeout must be a valid integer.")

def validate_retries(value):
    try:
        retries = int(value)

        if retries <= 0:
            raise argparse.ArgumentTypeError("ERROR\tNumber of retries must be a positive integer.")

        return retries

    except ValueError:
        raise argparse.ArgumentTypeError("ERROR\tNumber of retries must be a valid integer.")

def validate_port_num(value):
    try:
        port = int(value)

        if port < 0:
            raise argparse.ArgumentTypeError("ERROR\tPort number cannot be negative.")
        
        return port

    except ValueError:
        raise argparse.ArgumentTypeError("ERROR\tPort number must be a valid integer.")

def validate_server_ipv4(value):
    if not value.startswith('@'):
        raise argparse.ArgumentTypeError("ERROR\tServer address must start with '@'.")

    ipv4_str = value[1:]

    try:
        ipaddress.IPv4Address(ipv4_str)
        return ipv4_str
    except ipaddress.AddressValueError:
        raise argparse.ArgumentTypeError("ERROR\tInvalid IPv4 server address.")