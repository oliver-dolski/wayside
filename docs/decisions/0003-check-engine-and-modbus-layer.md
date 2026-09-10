# 0003: Silnik checkow i warstwa Modbus/TCP

## Kontekst

Trzy rozstrzygniecia Fazy 2, kazde z tego samego powodu: badanie projektowe
badaniu projektowym (architektura) powstalo przed pierwszym kodem tego projektu i przed
decyzja `LOCK-01` z Fazy 1 (`docs/decisions/0001-decoding-engine-v1.md`), wiec celowalo
w zakres szerszy niz zrealizowany v1. To ta sama klasa rozjazdu, co Pitfall 9 z
`01-RESEARCH.md` (rekomendacja `tshark` w `STACK.md` dla siedmiu protokolow v2+, zanim
zapadla decyzja o zawezeniu v1 do jednego protokolu przez scapy) - badanie na poziomie
projektu mierzylo scenariusz szerszy, a kod Fazy 2 rozstrzygnal wezej. Bez zapisu poza
katalogiem planowania kazda kolejna faza odtwarzalaby te trzy rozstrzygniecia po swojemu.

## Decyzja

### D-05: renderowanie raportu bez silnika szablonow

**Kontekst decyzji:** `ARCHITECTURE.md` rekomendowalo Jinja2 juz w pierwszym pionowym
przekroju (widoczne w tabeli odpowiedzialnosci komponentow i w kolejnosci budowy). Sekcja
"Context" w `PROJECT.md` stawia prostote nad kompletnoscia, a raport tej fazy ma szesc
sekcji o ustalonych z gory nazwach - staly szkielet nie potrzebuje silnika szablonow, zeby
zostac wyrenderowany.

**Rozstrzygniecie:** `src/wayside/report.py` renderuje markdown zwyklymi funkcjami Pythona
(sklejanie listy linii), bez zaleznosci od Jinja2 ani zadnego innego silnika szablonow.
Termin ponownego rozpatrzenia: Faza 4, gdy eksport do PDF bedzie znal liczbe wariantow
raportu i decyzja bedzie miala material do oceny, ktorego dzis brakuje.

**Bramka maszynowa:** brak wpisu `jinja2` w zaleznosciach `pyproject.toml`, oraz
`tests/test_report_render.py::test_six_sections_present` (kompletnosc szesciu sekcji bez
udzialu zadnego silnika szablonow).

### D-06: checki odnajdywane skanem katalogu w czasie dzialania

**Kontekst decyzji:** Kryterium rozszerzalnosci tej fazy mowi wprost o nowym checku bez
zmiany zadnego pliku w katalogu silnika. Entry points z `pyproject.toml` wymagalyby wpisu
w tym pliku i reinstalacji pakietu przy kazdym nowym checku. Rejestr oparty na dekoratorze
wymagalby centralnego importu, ktory rosnie z kazdym nowym checkiem - w obu przypadkach
dodanie checka dotyka pliku POZA jego wlasnym katalogiem.

**Rozstrzygniecie:** `src/wayside/checks/engine.py` odnajduje checki przez skan katalogu
(`sorted(rglob("*.yaml"))`) i laduje evaluator jako plik siostrzany przez
`importlib.util.spec_from_file_location`. Ani entry points, ani rejestr dekoratora. Nowy
check to nowy plik YAML plus nowy plik `.py` w nowym podkatalogu - `engine.py` i
`pyproject.toml` zostaja nietkniete.

**Bramka maszynowa:** `tests/test_check_engine.py::test_new_check_discovered_without_engine_change`
- dodaje check w czasie dzialania i porownuje sume sha256 `engine.py` oraz `pyproject.toml`
przed i po, zamiast zgadywac po samym wyniku dzialania.

### D-07: rozpoznanie protokolu i walidacja naglowka MBAP jako wlasny kod nad klasami PDU z biblioteki

**Kontekst decyzji:** Odczyt zrodla pakietu `scapy.contrib.modbus` potwierdzil, ze pokrycie
kodow funkcji Modbus Application Protocol jest kompletne - wlasny parser kodow funkcji nie
jest potrzebny. Ten sam odczyt pokazal dwie luki: biblioteka wiaze Modbusa na sztywno z
jednym numerem portu przez `bind_layers`, i nie ma zadnej walidacji naglowka MBAP - naglowek
o niepoprawnym identyfikatorze protokolu przechodzi bez zastrzezen, a puste bajty daja
fantomowy poprawny pakiet. Kryterium rozpoznania niezaleznego od portu nie da sie spelnic
przez samo bindowanie warstwy.

**Rozstrzygniecie:** `src/wayside/protocols/modbus_tcp.py` rozpoznaje Modbus/TCP po ksztalcie
naglowka MBAP na dowolnym porcie TCP, nie po numerze portu. Wlasna walidacja MBAP
(`validate_mbap`) stoi PRZED klasyfikacja funkcjonalna jako brama odrzucajaca ramke
niepoprawna calkowicie, nie jako ostrzezenie dolaczone do wyniku. Klasyfikacja kodow funkcji
pozostaje oparta na tabeli z biblioteki - zapasowa droga z mapy wymagan (wlasny parser kodow
funkcji) nie jest uruchamiana, bo pokrycie biblioteki okazalo sie kompletne.

**Bramka maszynowa:** fixture na porcie niestandardowym i fixture z uszkodzonym naglowkiem
MBAP, kazdy z parą testu jednostkowego i testu przez CLI -
`tests/test_modbus_tcp.py::test_recognizes_non_standard_port` /
`::test_recognizes_non_standard_port_end_to_end_via_cli` oraz
`::test_rejects_malformed_mbap` / `::test_rejects_malformed_mbap_end_to_end_via_cli`.

## Konsekwencje

Zaden z trzech wyborow nie zamyka drogi rozwoju - kazdy jest zapisany z wlasnym warunkiem
ponownego rozpatrzenia albo zapasowa droga, ktora zostala swiadomie NIE uruchomiona (D-07).
Kolejna faza, ktora chcialaby wprowadzic silnik szablonow, rejestr dekoratora czy wlasny
parser kodow funkcji Modbus, robi to jako swiadoma rewizje tego zapisu, nie jako pierwsze
rozpoznanie problemu.

## Odwracalnosc

D-05 i D-06 sa `two-way`: zmiana implementacji renderowania raportu albo mechanizmu
odnajdywania checkow nie dotyka schematu `analysis.json` ani kontraktu CLI, wiec koszt
rewizji jest lokalny do jednego modulu. D-07 jest `one-way` w granicach v1: rezygnacja z
wlasnej walidacji MBAP na rzecz gologo polegania na bibliotece oznaczalaby powrot dwoch
zamknietych luk (fantomowy pakiet z pustych bajtow, brak kontroli identyfikatora protokolu),
ktore ten zapis istnieje po to, zeby zamknac.

## Droga rewizji

W badaniu projektowym (architektura) dopisano note przy rekomendacjach drugiego dekodera
pakietow i silnika szablonow, wskazujaca na ten plik i na
`docs/decisions/0001-decoding-engine-v1.md` - badanie zostaje nietkniete jako zapis stanu
wiedzy sprzed kodu, nota jest wskazowka dla przyszlej lektury.
