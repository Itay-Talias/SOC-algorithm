from typing import List

from schemes.network_line import NetworkLine
from schemes.results import DataLeakageResults
from settings import WHITE_IPS, MAX_VOLUME


def map_volume_network(network_lines: List[NetworkLine]) -> DataLeakageResults:
    data_Leakage_results: DataLeakageResults = DataLeakageResults(dangerous_ips={})
    for network_line in network_lines:
        if network_line.source_ip in WHITE_IPS:
            if data_Leakage_results.dangerous_ips.get(network_line.destination_ip) is not None:
                data_Leakage_results.dangerous_ips[network_line.destination_ip] += network_line.volume
            else:
                data_Leakage_results.dangerous_ips[network_line.destination_ip] = network_line.volume

    return data_Leakage_results

def detect_ports_scan(network_lines: List[NetworkLine]) -> DataLeakageResults:
    data_leakage_results: DataLeakageResults = map_volume_network(network_lines)

    filtered_dangerous_ips = {
        ip: volumes for ip, volumes in data_leakage_results.dangerous_ips.items() if volumes > MAX_VOLUME
    }

    return DataLeakageResults(dangerous_ips=filtered_dangerous_ips)
