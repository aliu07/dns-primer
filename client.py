class DnsClient:
    def __init__(self, timeout, max_retries, port_num, query_flag, server_ip, domain_name):
        self.timeout = timeout
        self.max_retries = max_retries
        self.port_num = port_num
        self.query_flag = query_flag
        self.server_ip = server_ip
        self.domain_name = domain_name

    def query(self):
        print("Hello world!")
        print(self.timeout)