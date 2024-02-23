from typing import List

from schemes.network_line import NetworkLine
import pandas as pd

def read_excel_to_network_lines(file_path: str) -> List[NetworkLine]:
    # Read the Excel file into a pandas DataFrame
    df = pd.read_excel(file_path)

    network_lines = []

    # Iterate over rows in the DataFrame and create NetworkLine instances
    for index, row in df.iterrows():
        network_line = NetworkLine(
            line_number=row['line'],
            source_ip=row['source_ip'],
            destination_ip=row['destination_ip'],
            source_port=row['source_port'],
            destination_port=row['destination_port'],
            body=row['body']
        )
        network_lines.append(network_line)

    return network_lines
