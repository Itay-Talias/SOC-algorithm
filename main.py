from attacks_detection.data_leakage import map_volume_network
from attacks_detection.port_scan import detect_ports_scan
from attacks_detection.sql_injection import detect_sql_injection
from helpers.execl_helper import read_excel_to_network_lines
from schemes.results import Results

from settings import FILE_PATH

results: Results = Results()
network_lines = read_excel_to_network_lines(FILE_PATH)
results.sql_injection_results = detect_sql_injection(network_lines)
results.port_scan_potential_results = detect_ports_scan(network_lines)
results.data_leakage_results = map_volume_network(network_lines)
print(results.json())
