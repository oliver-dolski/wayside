# 0001: Silnik dekodowania v1

## Kontekst

`.planning/research/STACK.md` (badanie projektowe z 2026-09-01, sekcja "Core Technologies")
rekomenduje `tshark` (Wireshark CLI, wywoływany jako subprocess) jako główny silnik
dekodowania dla siedmiu protokołów przemysłowych docelowych dla v2+: Modbus, S7comm, DNP3,
EtherNet/IP+CIP, PROFINET, OPC UA i IEC 60870-5-104/101. Rekomendacja jest uzasadniona
w tamtym badaniu wprost: scapy pokrywa natywnie tylko 2 z 7 protokołów, a Wireshark ma
dissectory dla wszystkich siedmiu.

Dokumenty nadrzędne i późniejsze w czasie - `ROADMAP.md`, `01-01-SUMMARY.md` i
`REQUIREMENTS.md` - rozstrzygają węziej: zakres v1 to wyłącznie Modbus/TCP, dekodowany
przez `scapy` natywnie, bez żadnej zależności od Wiresharka ani tsharka. `FOUND-01` mówi
to wprost: "Narzędzie uruchamia się na czystym Windows 11 jednym poleceniem, bez
instalowania Wiresharka ani tsharka".

To jest kolizja między dwoma badaniami projektowymi o różnym zakresie czasowym i
ambicji, opisana jako Pitfall 9 w `01-RESEARCH.md`: `STACK.md` mierzył scenariusz szerszy
(siedem protokołów, v2+), zanim zapadła decyzja o zawężeniu v1 do jednego protokołu.

## Decyzja

Obowiązuje rozstrzygnięcie węższe. Zewnętrzny dysektor (Wireshark/tshark, oraz `pyshark`
jako jego opakowanie w PyPI) jest wykluczony z v1 - nie tylko jako zależność wymagana, ale
też jako zależność opcjonalna. Zależność opcjonalna i tak pojawia się w instrukcji
instalacji i w dokumentacji, a `FOUND-01` mówi o czystej maszynie: brak dodatkowej
instalacji sieciowej, nie tylko brak instalacji domyślnej.

Ta decyzja jest egzekwowana maszynowo przez `tests/test_no_external_dissector.py`, które
skanuje `src/`, `scripts/`, `pyproject.toml`, `uv.lock` i `.github/workflows/` pod kątem
nazw binarek (`tshark`, `wireshark`) oraz nazwy pakietu opakowującego (`pyshark`), oraz
osobno pilnuje regresji na Assumption A1 (brak importu `scapy.all`, który na Windows
transitywnie ładuje `scapy.arch.libpcap` i łamie deklarowaną bezzależnościowość).

## Konsekwencje

Kolejne protokoły przemysłowe w v1 (poza Modbus/TCP) wymagają własnego parsera, napisanego
ręcznie na podstawie publicznej dokumentacji protokołu, zamiast delegacji do gotowego
dissectora Wiresharka. `ROADMAP.md` (Faza 2) nazywa to wprost atutem, nie kosztem: ręczne
parsowanie protokołu pokazuje znajomość protokołu, nie znajomość biblioteki, a to jest
przewaga, na której ten projekt stoi (patrz `PROJECT.md`, sekcja "Context").

Zakres bramki jest kosztowny do zmiany w drugą stronę: każda kolejna faza rośnie pod nią,
więc późniejsze rozszerzenie zakresu skanu (na przykład o nowy nośnik zależności, jak plik
konfiguracyjny narzędzia deweloperskiego) wymaga przejrzenia wszystkiego, co pod nim
powstało do tego momentu.

## Odwracalnosc

`one-way` w granicach v1. Dopóki v1 trwa, żadna faza nie wprowadza zależności od
zewnętrznego dekodera pakietów, nawet jako opcjonalnej. Cofnięcie tej decyzji w trakcie v1
oznaczałoby złamanie `FOUND-01` wprost.

## Droga rewizji

`V2-03` (`.planning/REQUIREMENTS.md`, sekcja "v2 Requirements") dopuszcza wprost zewnętrzny
dekoder (tshark) dla kolejnych protokołów przemysłowych (S7comm, DNP3, IEC 60870-5-104) jako
udokumentowany wymóg wstępny. Rewizja tej decyzji należy do v2 i wymaga zmiany wymagania
w `REQUIREMENTS.md`, nie samej zmiany kodu - `tests/test_no_external_dissector.py` musi
zostać świadomie zawężony albo zdjęty razem z tą zmianą wymagania, inaczej bramka i
wymaganie zaczną sobie przeczyć.

Przy okazji Fazy 2 warto dopisać notę do `.planning/research/STACK.md`, że rekomendacja
tshark w tamtym badaniu dotyczy zakresu szerszego (siedem protokołów, v2+) niż zrealizowany
zakres v1 (jeden protokół, Modbus/TCP przez scapy) - żeby przyszła lektura tamtego dokumentu
nie odczytała rekomendacji jako wciąż aktualnej dla v1.
