from typing import List

from schemes.network_line import NetworkLine
from schemes.results import PortScanPotentialResults
from settings import WHITE_IPS, WHITE_PORTS, WHITE_NUMBER_PORTS


def map_ips_ports(network_lines: List[NetworkLine]) -> PortScanPotentialResults:
    sql_injection_results: PortScanPotentialResults = PortScanPotentialResults(dangerous_ips={})
    for network_line in network_lines:
        if network_line.source_ip not in WHITE_IPS and network_line.destination_port not in WHITE_PORTS:
            if sql_injection_results.dangerous_ips.get(network_line.source_ip) is not None:
                sql_injection_results.dangerous_ips[network_line.source_ip] += 1
            else:
                sql_injection_results.dangerous_ips[network_line.source_ip] = 1

    return sql_injection_results


def detect_ports_scan(network_lines: List[NetworkLine]) -> PortScanPotentialResults:
    port_scan_potential_results: PortScanPotentialResults = map_ips_ports(network_lines)

    # Filter the dangerous_ips dictionary to include only entries where the list of ports has a size of
    # WHITE_NUMBER_PORTS

    filtered_dangerous_ips = {
        ip: ports for ip, ports in port_scan_potential_results.dangerous_ips.items() if ports > WHITE_NUMBER_PORTS
    }

    # Create a new PortScanPotentialResults object with the filtered dangerous_ips
    return PortScanPotentialResults(dangerous_ips=filtered_dangerous_ips)
