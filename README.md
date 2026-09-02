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
```

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
