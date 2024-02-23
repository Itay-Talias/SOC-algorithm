from pydantic import BaseModel


class NetworkLine(BaseModel):
    line_number: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    body: str

