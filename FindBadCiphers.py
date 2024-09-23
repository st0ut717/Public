import nmap3
import socket
import ssl
from  OpenSSL import SSL

# Find open https
def scan_subnet(subnet, port=443):
    print(f'scan_subnet function called')
    net_map = nmap3.NmapScanTechniques()
    scan_result = net_map.nmap_tcp_scan(subnet, args=f'-p {port} --open')
    servers = []
    for host, details  in scan_result.items():
        if 'ports' in details:
            for port_info in details['ports']:
                if port_info['portid'] == str(port) and port_info['state'] == 'open':
                    servers.append(host)
    return servers

# determine TLS/SSL version
def get_ssl_tls_version(host, port=443):
    try:
        context = SSL.Context(SSL.SSLv23_METHOD)
        conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        conn.set_tlsext_host_name(host.encode())
        conn.connect((host,port))
        conn.setblocking(1)
        conn.do_handshake()
        cipher = conn.get_cipher_name()
        version = conn.get_protocol_version_name()
        conn.close()
        return version
    except Exception as e:
        return None

# check for TLS 1.0.1. or SSL
def check_servers_for_weak_ssl(servers):
    vulnerable_servers = []
    for server in servers:
        print(server)
        version = get_ssl_tls_version(server)
        print(version)
        if version is ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
            vulnerable_servers.append((server, version))
            print(vulnerable_servers)
    return vulnerable_servers
    


# primary function
def find_vulnerable_servers(subnet):
    print(f'Scanning subnet: {subnet} for open HTTPS servers...')
    servers = scan_subnet(subnet)
    print(f'\nFound {len(servers)} servers with open HTTPS')

    print(f'\nChecking TLS/SSL versions..')
    vulnerable_servers = check_servers_for_weak_ssl(servers)

    if vulnerable_servers:
        print(f'\nVulnerable servers found:')
        for server, version in vulnerable_servers:
            print(f'\nServer: {server}, SSL/TLS Version: {version}')
        else:
            print(f'\nNo vulnerabls HTTP cipers found')

subnet_to_scan = input('input subnet to scan, (e.g.192.168.1.0/24)')
find_vulnerable_servers(subnet_to_scan)
