from typing import Any, Dict, List, Optional


class InMemoryDB:
    def __init__(self) -> None:
        self._esxi_hosts: List[Dict[str, Any]] = []
        self._switches: List[Dict[str, Any]] = []
        self._correlations: List[Dict[str, Any]] = []

    def save_esxi_hosts(self, hosts: List[Dict[str, Any]]) -> None:
        self._esxi_hosts = hosts

    def save_switches(self, switches: List[Dict[str, Any]]) -> None:
        self._switches = switches

    def save_correlation(self, correlation: Dict[str, Any]) -> None:
        self._correlations = [correlation]

    def get_esxi_hosts(self) -> List[Dict[str, Any]]:
        return self._esxi_hosts

    def get_switches(self) -> List[Dict[str, Any]]:
        return self._switches

    def get_latest_correlation(self) -> Optional[Dict[str, Any]]:
        if not self._correlations:
            return None
        return self._correlations[-1]


db = InMemoryDB()
