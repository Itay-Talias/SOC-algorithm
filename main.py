from attacks_detection.sql_injection import detect_sql_injection
from helpers.execl_helper import read_excel_to_network_lines

from settings import FILE_PATH

network_lines = read_excel_to_network_lines(FILE_PATH)
detect_sql_injection(network_lines)