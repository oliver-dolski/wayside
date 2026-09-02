"""Deterministyczny generator syntetycznych zrzutow pcap Modbus/TCP.

Uzycie:
    uv run python scripts/gen_fixtures.py            # regeneruje fixture'y w miejscu
    uv run python scripts/gen_fixtures.py --check    # regeneruje do katalogu tymczasowego
                                                       # i porownuje sume sha256 z plikami
                                                       # w repozytorium

Adresacja pochodzi wylacznie z zakresu dokumentacyjnego RFC 5737 (192.0.2.0/24).
Adresy MAC sa lokalnie administrowane i wymyslone, nie naleza do zadnego realnego
urzadzenia. Znaczniki czasu sa stale (`BASE_TIMESTAMP + i * 0.01`), nigdy
`time.time()` - patrz Pitfall 5 w 01-RESEARCH.md. `wrpcap()` domyslnie zapisuje
klasyczny format pcap (nie pcapng), wiec plik nie ma miejsca na metadane maszyny.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
import tempfile
from pathlib import Path

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.contrib.modbus import (  # noqa: E402
    ModbusADURequest,
    ModbusADUResponse,
    ModbusPDU06WriteSingleRegisterRequest,
    ModbusPDU06WriteSingleRegisterResponse,
)
from scapy.layers.inet import IP, TCP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

# Adresacja dokumentacyjna, RFC 5737.
CLIENT_MAC = "02:00:00:00:00:01"
SERVER_MAC = "02:00:00:00:00:02"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
MODBUS_PORT = 502
BASE_TIMESTAMP = 1700000000.0

FIXTURE_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "pcap"
FIXTURE_NAME = "modbus_write_single_register.pcap"

__all__ = ["gen_modbus_write_single_register", "main"]


def gen_modbus_write_single_register(output_dir: Path) -> Path:
    """Generuje jedna wymiane Modbus/TCP (zadanie i odpowiedz 0x06) do pliku pcap.

    Zwraca sciezke do wygenerowanego pliku. Dwa kolejne wywolania produkuja
    bajtowo identyczny plik (stale adresy, stale znaczniki czasu).
    """
    request = (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=CLIENT_IP, dst=SERVER_IP, id=1)
        / TCP(sport=50000, dport=MODBUS_PORT, seq=1, ack=0, flags="PA")
        / ModbusADURequest(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterRequest(registerAddr=0x0001, registerValue=0x002A)
    )
    response = (
        Ether(src=SERVER_MAC, dst=CLIENT_MAC)
        / IP(src=SERVER_IP, dst=CLIENT_IP, id=1)
        / TCP(sport=MODBUS_PORT, dport=50000, seq=1, ack=1, flags="PA")
        / ModbusADUResponse(transId=1, protoId=0, unitId=1)
        / ModbusPDU06WriteSingleRegisterResponse(registerAddr=0x0001, registerValue=0x002A)
    )

    packets = [request, response]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIMESTAMP + i * 0.01

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / FIXTURE_NAME
    wrpcap(str(output_path), packets)
    return output_path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _check() -> int:
    repo_file = FIXTURE_DIR / FIXTURE_NAME
    if not repo_file.exists():
        print(f"Brak pliku fixture w repozytorium: {repo_file}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        generated = gen_modbus_write_single_register(Path(tmp))
        repo_hash = _sha256(repo_file)
        generated_hash = _sha256(generated)
        if repo_hash != generated_hash:
            print(
                f"Rozjazd sumy sha256 dla {FIXTURE_NAME}: "
                f"repo={repo_hash} wygenerowano={generated_hash}",
                file=sys.stderr,
            )
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Regeneruj do katalogu tymczasowego i porownaj sume sha256 z repozytorium.",
    )
    args = parser.parse_args()

    if args.check:
        return _check()

    output_path = gen_modbus_write_single_register(FIXTURE_DIR)
    print(f"Wygenerowano: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
