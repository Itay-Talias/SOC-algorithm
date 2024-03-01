import re
from typing import List

from schemes.network_line import NetworkLine
from schemes.results import SqlInjectionResults


def monitor_network_line(network_line: NetworkLine):
    # Simulated function to monitor user input
    # Replace this with actual code to monitor user input
    # Here, we're using a regular expression to check for common SQL injection patterns
    sql_injection_pattern = re.compile(r"[-;'\"=*]")
    if sql_injection_pattern.search(network_line.body):
        return True  # SQL injection pattern detected
    return False


# Function to detect SQL injection attacks
def detect_sql_injection(network_lines: List[NetworkLine]) -> SqlInjectionResults:
    sql_injection_results: SqlInjectionResults = SqlInjectionResults(dangerous_sql_injection_lines=[])
    for network_line in network_lines:
        if monitor_network_line(network_line):
            sql_injection_results.dangerous_sql_injection_lines.append(network_line.line_number)
            print(f'Potential SQL injection attack detected in line {network_line.line_number}!')

    return sql_injection_results
