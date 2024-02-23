from typing import List

from pydantic import BaseModel


class SqlInjectionResults(BaseModel):
    dangerous_sql_injection_lines: List[int]



class Results(BaseModel):
    sql_injection_results: SqlInjectionResults
