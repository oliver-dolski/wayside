# Wayside

Wayside to pasywne narzedzie do oceny bezpieczenstwa sieci OT/ICS: na wejsciu dostaje
zrzut ruchu (pcap), a na wyjsciu daje inwentaryzacje zasobow, mape komunikacji i liste
findingow, gdzie kazdy finding ma powolanie na konkretny punkt normy. Narzedzie nigdy
nie wysyla ani jednego pakietu do sieci - caly odczyt dzieje sie z pliku.

## Bootstrap

Wymagania wstepne: Windows 11, Windows PowerShell 5.1, git. Wireshark, tshark ani
sterownik przechwytywania (Npcap) nie sa potrzebne.

Jedno polecenie po klonie:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\bootstrap.ps1
```

Ostatnim krokiem tego polecenia jest instalacja haka pre-commit
(`uv run pre-commit install`). Jest to osobny krok, bo git swiadomie NIE
kopiuje `.git/hooks/*` przy klonowaniu (hak w cudzym repozytorium moglby
wykonac dowolny kod przy pierwszym commicie) - bez tego kroku bramka
poufnosci opisana nizej istnieje jako kod, ale nigdy nie zostaje uruchomiona.

## Bramka poufnosci

Kazdy `git commit` przechodzi przez `scripts/confidentiality_guard.py`
w trzech warstwach:

1. **Sciezkowa** - kazdy plik pod `standards/.local/` jest odrzucany,
   niezaleznie od tresci, nawet gdy zostal dodany przez `git add -f`.
2. **Korpusowa** - porownuje commitowana tresc z lokalnym, gitignorowanym
   katalogiem `standards/.local` (shingle dwunastowyrazowe, skroty sha256,
   nigdy surowy tekst). Dziala WYLACZNIE lokalnie, tam gdzie ten katalog
   moze istniec.
3. **Strukturalna** - regex na odcisk jezyka normatywnego (kropkowany numer
   punktu + modalnosc normatywna w tej samej linii). Dziala bez zadnego
   korpusu, wiec takze w CI.

Katalog `standards/.local` nigdy nie opuszcza maszyny autora - jest
gitignorowany i **nie wolno** go wysylac do sekretow repozytorium ani do
zadnej konfiguracji CI, bo to zniweczyloby cel tej bramki.

**Granice, nazwane wprost, a nie przemilczane:**

- Lokalny hak jest warstwa prewencyjna WYLACZNIE dla commitow wykonanych
  normalnie. Omija sie go swiadomie flaga `git commit --no-verify` - to jest
  wlasciwosc kazdego lokalnego haka git, nie luka tej implementacji.
- Warstwa uruchamiana w CI jest **detekcyjna, nie prewencyjna** - wykrywa po
  fakcie (juz po `git push`) i nie powstrzymuje samego wyslania tresci. CI
  nie ma tez dostepu do `standards/.local` (gitignorowany), wiec w CI dziala
  wylacznie warstwa strukturalna.

## Uruchomienie

```powershell
uv run wayside inspect <plik.pcap>
uv run wayside analyze <plik.pcap> --out-dir wayside-out
```

Komenda `analyze` zapisuje w katalogu wyjsciowym `analysis.json` (model
maszynowy) i `report.md` (raport w markdown). Flaga `--pdf` dokladajac
trzeci artefakt, `report.pdf`, z osadzonym fontem Unicode (DejaVu Sans) -
polskie znaki diakrytyczne wygladaja przez to tak samo na kazdej maszynie,
niezaleznie od zainstalowanych fontow systemowych. Flaga jest domyslnie
wylaczona: domyslna sciezka narzedzia nie zyskuje przez to nowej zaleznosci
uruchomieniowej.

```powershell
uv run wayside analyze <plik.pcap> --pdf --out-dir wayside-out
```

## Przykladowy raport

Katalog [`examples/4sics/`](examples/4sics/) niesie gotowy przykladowy
raport (`analysis.json`, `report.md`, `report.pdf`) wygenerowany z
publicznego zbioru 4SICS Geek Lounge.

Ruch pochodzi z laboratorium 4SICS Geek Lounge (2015), udostepniony
publicznie przez Netresec (https://www.netresec.com/) za zgoda CS3Sthlm
(nastepcy konferencji 4SICS) na udostepnienie przechwyconego ruchu.

Strona zbioru: [https://www.netresec.com/?page=PCAP4SICS](https://www.netresec.com/?page=PCAP4SICS).
Raport jest odtwarzalny ze skryptu pobierajacego - zaden plik zrzutu tego
zbioru nie jest sledzony przez gita. Szczegoly, atrybucja pelna i granica
dziedzinowa stoja w [`examples/4sics/README.md`](examples/4sics/README.md).

## Stan weryfikacji powolan na normy

Kazdy finding niesie powolanie na punkt normy razem z sygnatura i edycja, a
kazde powolanie niesie takze informacje o tym, czy numeracja tego punktu
zostala zestawiona z legalnym egzemplarzem dokumentu.

IEC 62443-3-3: na moment pisania egzemplarz jest NIEZAKUPIONY, wiec numeracja
wszystkich punktow tego dokumentu w katalogu norm jest prowizoryczna, a
kazde powolanie na nia niesie znacznik `verified: no` - dokument jest
platny. Droga rozstrzygniecia i podzial miedzy oba dokumenty opisuje
`docs/decisions/0006-weryfikacja-powolan-wobec-egzemplarza-normy.md`.

CLC/TS 50701:2023: sygnatura i edycja sa potwierdzone u zrodla
(`docs/decisions/0004-sygnatura-clc-ts-50701.md`); numeracja punktow nie
jest potwierdzona i z zasady nie bedzie, bo tego egzemplarza projekt nie
kupuje. Dokument ma status specyfikacji technicznej, nie normy europejskiej,
wiec stosuje sie go dobrowolnie. Pole punktu obu wpisow tego dokumentu w
katalogu norm niesie jawnie prowizoryczny token, nigdy liczbe wygladajaca
jak numer punktu.

Droga podniesienia znacznika: zakup egzemplarza, przeczytanie punktow wobec
niego, edycja DWOCH pol - pola weryfikacji i pola prowieniencji tytulu
punktu (`clause_title_source`) - w pliku katalogu norm. Warstwa wczytujaca
odrzuca wpis, ktory podnosi jedno z tych dwoch pol bez drugiego. Zaden plik
kodu przy tym nie zmienia sie.

Tytul punktu, ktory nie zostal przepisany z egzemplarza, renderuje sie w
raporcie jako opis wlasny, w innym ksztalcie niz tytul potwierdzony.

## Testy

```powershell
uv run pytest
```

## Weryfikacja w CI

Kazdy `push` i `pull_request` uruchamia `.github/workflows/ci.yml` na
`windows-latest` - platforma docelowa projektu to Windows 11, wiec pakiet
zielony wylacznie na Linuksie nie dowodziby, ze narzedzie dziala tam, gdzie
ma dzialac. Dwa joby:

1. **`test`** - pelny pakiet testow na swiezym checkoucie: `uv sync --locked`,
   krok bramki kompletnosci kolekcji (sprawdza, ze piec modulow krytycznych
   fazy 1 nie zniknelo z kolekcji `pytest`), potem `uv run pytest`.
2. **`confidentiality-backstop`** - detekcyjny backstop poufnosci: checkout
   z `fetch-depth: 0` (pelna historia), `scripts/confidentiality_guard.py`
   w trybie `--no-corpus` na wszystkich sledzonych plikach, oraz
   `git log --all -- standards/.local`, ktory konczy job bledem, gdy wynik
   nie jest pusty.

**Czego CI z zalozenia NIE widzi:** lokalnego korpusu `standards/.local`.
Katalog jest gitignorowany i nigdy nie trafia do zdalnego repozytorium ani do
sekretow CI - to jest architektoniczna koniecznosc, nie niedopatrzenie: wgranie
korpusu do sekretow repozytorium zniweczyloby cel calej bramki. W CI dziala
wylacznie warstwa strukturalna (regex na odcisk jezyka normatywnego) i
kontrola sciezki - nigdy warstwa korpusowa.

**Charakter tej warstwy jest detekcyjny, nie prewencyjny.** CI potwierdza
naruszenie PO fakcie - juz po `git push` - i uruchamia reakcje: revert,
przepisanie historii przez `git filter-repo` przed jakimkolwiek publicznym
pushem, nigdy nie powstrzymuje samego wyslania tresci. Konto osobiste w
GitHub.com nie ma server-side pre-receive hookow, wiec twarda prewencja po
stronie zdalnej nie jest w tym projekcie dostepna. Zielone CI potwierdza, ze
nic, co bramka rozpoznaje, nie przeszlo przy TYM pushu - to nie jest dowod
szczelnosci w ogole.

Granice lokalnego haka pre-commit (drugiej strony tej samej bramki) opisane
sa w sekcji `## Bramka poufnosci` wyzej - oba opisy stoja obok siebie, zeby
sobie nie zaprzeczac.
