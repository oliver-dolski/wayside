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
