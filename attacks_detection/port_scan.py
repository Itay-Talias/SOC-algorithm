from typing import List

from schemes.network_line import NetworkLine
from schemes.results import PortScanPotentialResults
from settings import WHITE_IPS, WHITE_PORTS


def map_ips_ports(network_lines: List[NetworkLine]) -> PortScanPotentialResults:
    sql_injection_results: PortScanPotentialResults = PortScanPotentialResults(dangerous_ips={})
    for network_line in network_lines:
        if network_line.source_ip not in WHITE_IPS and network_line.destination_port not in WHITE_PORTS:
            if sql_injection_results.dangerous_ips.get(network_line.source_ip) is not None:
                sql_injection_results.dangerous_ips[network_line.source_ip].append(network_line.destination_port)
            else:
                sql_injection_results.dangerous_ips[network_line.source_ip] = [network_line.destination_port]

    return sql_injection_results
