from typing import List, Optional

from pydantic import BaseModel


class PortScanPotentialResults(BaseModel):
    dangerous_ips: dict


class SqlInjectionResults(BaseModel):
    dangerous_sql_injection_lines: List[int]


class Results(BaseModel):
    sql_injection_results: SqlInjectionResults = None
    port_scan_potential_results: PortScanPotentialResults = None
