# Przykladowy raport: zbior 4SICS

Atrybucja jest warunkiem licencyjnym redystrybucji tego materialu, nie
uprzejmoscia - kopiujac ten katalog, kopiuje sie razem z nim ten warunek.

## Atrybucja

Ruch pochodzi z laboratorium 4SICS Geek Lounge (2015), udostepniony
publicznie przez Netresec (https://www.netresec.com/) za zgoda CS3Sthlm
(nastepcy konferencji 4SICS) na udostepnienie przechwyconego ruchu.

Strona zbioru: [https://www.netresec.com/?page=PCAP4SICS](https://www.netresec.com/?page=PCAP4SICS).
Strona instytucji, ktorej atrybucja sie nalezy: [CS3Sthlm](https://cs3sthlm.se/).
Redystrybucja jest dozwolona, takze w materialach szkoleniowych, pod
warunkiem tej atrybucji i odeslania do strony Netresec.

## Granica dziedzinowa

Ten ruch pochodzi z laboratorium konferencji przemyslowej, NIE z instalacji
kolejowej. Przykladowy raport ponizej nie pokazuje dziedziny, w
ktorej ten projekt ma swoj wyroznik - to jest ryzyko rezydualne przyjete
swiadomie i zapisane w
[`docs/decisions/0005-zbior-publiczny-dla-przykladu-raportu.md`](../../docs/decisions/0005-zbior-publiczny-dla-przykladu-raportu.md):
publiczny punkt pobrania z prawdziwym ruchem kolejowym nie istnieje, a
odtwarzalnosc bije wartosc dziedzinowa. Czytelnik szukajacy dowodu z
sektora kolejowego nie znajdzie go w tym katalogu.

## Odtworzenie

Dwa polecenia, w tej kolejnosci:

```powershell
uv run python scripts\fetch_4sics_sample.py
uv run python scripts\gen_example_report.py
```

Pierwsze polecenie pobiera plik zrodlowy zbioru (okolo 200 MB) ze strony
Netresec, weryfikuje jego sume sha256 wobec stalej zapisanej w
`scripts/fetch_4sics_sample.py` i konczy sie bledem przy niezgodnosci -
cicha podmiana pliku u zrodla zostanie wiec wykryta, nie cicho uzyta. Potem
buduje deterministyczny podzbior 40 pakietow (`4sics-slice.pcap`) i
weryfikuje jego sume tak samo. Drugie polecenie generuje trzy artefakty
ponizej z tego podzbioru, ze stalym znacznikiem czasu.

## Co ten raport pokazuje

- **Streszczenie** - liczba findingow tego przebiegu.
- **Zakres** - rozpoznane protokoly, okno czasowe, snaplen.
- **Metodyka** - kryteria rubryki wagi, bez wymyslonej skali.
- **Inwentarz** - osiem hostow zaobserwowanych w podzbiorze, z producentem
  wyprowadzonym z adresu MAC tam, gdzie dalo sie go ustalic.
- **Macierz komunikacji** - siedem sesji TCP z ladunkiem.
- **Findingi** - piec wystapien checka `unauthenticated-industrial-protocol`
  (jeden host odpytujacy piec roznych serwerow Modbus/TCP bez mechanizmu
  uwierzytelnienia), kazde z powolaniem na IEC 62443-3-3 i na CLC/TS 50701.
  Ten sam wzorzec jest teraz czytelny wprost z blokow findingu w
  `report.md`/`report.pdf` - kazdy blok niesie linie uczestnikow sesji
  (`Uczestnicy sesji: <zrodlo> -> <cel>`) z tym samym adresem zrodlowym i
  piecioma roznymi adresami docelowymi.
- **Zalecenia** - jedno zalecenie, wspolne dla wszystkich pieciu findingow,
  z liczba findingow, ktorych dotyczy.

Numeracja punktow normy w powolaniach jest prowizoryczna - `report.md` i
`report.pdf` niosa przy kazdym powolaniu znacznik
`PROWIZORYCZNE, NIEZWERYFIKOWANE`. Powod i droga rozstrzygniecia stoi w
sekcji `## Stan weryfikacji powolan na normy` glownego
[`README.md`](../../README.md) tego repozytorium - ten katalog nie powtarza
tamtej tresci.

## Trzy artefakty

- `analysis.json` - model maszynowy tego przebiegu.
- `report.md` - ten sam model, w markdown.
- `report.pdf` - ten sam model, w postaci gotowej do wyslania, z osadzonym
  fontem Unicode (DejaVu Sans).
