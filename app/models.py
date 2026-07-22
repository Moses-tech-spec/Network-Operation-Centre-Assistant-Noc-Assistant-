from pydantic import BaseModel


class MemoryInfo(BaseModel):
    free_mb: int
    total_mb: int


class SystemInfo(BaseModel):
    identity: str
    version: str
    uptime: str
    cpu_load: int
    memory: MemoryInfo


class RouterStatus(BaseModel):
    router: str
    status: str
    system: SystemInfo
