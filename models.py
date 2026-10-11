from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    id: str
    title: str
    status: str      # "pass" | "fail" | "info"
    severity: str    # "high" | "medium" | "low" | "info"
    detail: str
    fix: str = ""
    controls: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)
