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

## Intended Use

Narzedzie czyta wylacznie plik ze zrzutem ruchu; pod katalogiem `src/wayside`
nie ma ani jednego importu modulu sieciowego, co pilnuje test
`tests/test_oui.py::test_no_network_module_imports_under_src_wayside`. Granica
tego dowodu jest nazwana wprost w tym samym akapicie: bramka pilnuje importow
w kodzie zrodlowym, a nie faktycznego braku ruchu w czasie dzialania, wiec
dowodzi, ze narzedzie nie MA jak wyslac pakietu, a nie tego, ze go nie
wyslalo.

### Do czego

- Ocena bezpieczenstwa w punkcie czasu z gotowego zrzutu ruchu.
- Inwentarz zaobserwowanych urzadzen.
- Macierz komunikacji.
- Findingi z powolaniem na punkt normy.
- Material do raportu dla wlasciciela systemu.

### Do czego nie

- Nie jest ciaglym monitoringiem sieci.
- Nie jest skanerem aktywnym ani narzedziem testu penetracyjnego.
- Nie wydaje oceny, czy instalacja spelnia albo nie spelnia wymagan normy.
- Nie podaje liczbowego poziomu bezpieczenstwa.

### Warunek uzycia

Zrzut ruchu z cudzej sieci wolno analizowac wylacznie za zgoda wlasciciela
tej sieci. Narzedzie tej zgody nie sprawdza ani sprawdzic nie moze -
pasywnosc narzedzia nie jest odpowiedzia na pytanie o legalnosc posiadania
zrzutu.

## Bramka poufnosci

Kazdy `git commit` przechodzi przez `scripts/confidentiality_guard.py`
w czterech warstwach:

1. **Sciezkowa** - kazdy plik pod `standards/.local/` jest odrzucany,
   niezaleznie od tresci, nawet gdy zostal dodany przez `git add -f`.
2. **Korpusowa** - porownuje commitowana tresc z lokalnym, gitignorowanym
   katalogiem `standards/.local` (shingle dwunastowyrazowe, skroty sha256,
   nigdy surowy tekst). Dziala WYLACZNIE lokalnie, tam gdzie ten katalog
   moze istniec.
3. **Strukturalna** - regex na odcisk jezyka normatywnego (kropkowany numer
   punktu + modalnosc normatywna w tej samej linii). Dziala bez zadnego
   korpusu, wiec takze w CI.
4. **Tozsamosciowa** - piec regul lapiacych tresc z sieci pracodawcy zamiast
   tresci normy: adresacja prywatna RFC 1918, adres sprzetowy jako sygnatura
   urzadzenia, nazwa urzadzenia, oraz nazwa wlasna projektu odgrodzonego
   granica poufnosci autora - te cztery sa regulami KSZTALTU, zbudowanymi
   z publicznie znanych skrotow branzowych i z ksztaltow adresowych, nigdy
   z niczyjego inwentarza, i dzialaja bez zadnego lokalnego materialu, a wiec
   takze w CI. Piata regula jest literalna i dziala WYLACZNIE lokalnie, z
   pliku gitignorowanego. Adres obecny w repozytorium musi byc zadeklarowany
   po wartosci razem z pochodzeniem w `.confidentiality-allow` - adres
   niezadeklarowany zapala bramke niezaleznie od pliku, w ktorym stoi.

Katalog `standards/.local` nigdy nie opuszcza maszyny autora - jest
gitignorowany i **nie wolno** go wysylac do sekretow repozytorium ani do
zadnej konfiguracji CI, bo to zniweczyloby cel tej bramki.

**Granice, nazwane wprost, a nie przemilczane:**

- Lokalny hak jest warstwa prewencyjna WYLACZNIE dla commitow wykonanych
  normalnie. Omija sie go swiadomie flaga `git commit --no-verify` - to jest
  wlasciwosc kazdego lokalnego haka git, nie luka tej implementacji.
- Warstwa uruchamiana w CI jest **detekcyjna, nie prewencyjna** - wykrywa po
  fakcie (juz po `git push`) i nie powstrzymuje samego wyslania tresci. CI
  nie ma tez dostepu do `standards/.local` (gitignorowany), wiec w CI dzialaja
  wylacznie warstwa strukturalna i cztery reguly ksztaltu warstwy
  tozsamosciowej.
- Piata regula warstwy tozsamosciowej, literalna, dziala WYLACZNIE lokalnie -
  plik z literalami jest gitignorowany i **nie wolno** go wgrywac do
  sekretow repozytorium ani do konfiguracji CI, bo to zniweczyloby cel tej
  warstwy dokladnie tak samo, jak wgranie korpusu norm zniweczyloby warstwe
  2. Brak tego pliku jest zglaszany ostrzezeniem na standardowe wyjscie
  bledu, nie przemilczany.
- Sam skrypt bramki czyta wylacznie tresc tekstowa (importuje wylacznie
  biblioteke standardowa Pythona), wiec plikow binarnych nie obejmuje -
  obejmuje je osobny test pakietu, dzialajacy po warstwie tekstowej tych
  plikow, bo skrypt musi dzialac bez zaleznosci zewnetrznych, a czytnik PDF
  zaleznoscia jest.
- Wzorce warstwy tozsamosciowej sa wzorcami ksztaltu, wiec lapia konwencje
  nazewnicza, a nie kazda mozliwa nazwe - literaly, ktorych zaden ksztalt nie
  wyraza, sa rola piatej reguly, lokalnej.

**Trafienie w BIEZACYM drzewie naprawia sie poprawka przed commitem. Trafienie
w HISTORII to zupelnie inna sytuacja: tresc jest juz zapisana i zaden kolejny
commit tego nie cofa.** Droga naprawy to przepisanie historii przez
`git filter-repo` PRZED jakimkolwiek publicznym pushem. Jesli publiczny push
juz sie odbyl, przepisanie historii nie cofa faktu, ze tresc mogla zostac
zescrapowana albo zmirrorowana - ten kontrakt dotyczy kazdego wzorca tej
bramki, nie tylko sciezki `standards/.local`.

## Uruchomienie

```powershell
uv run wayside inspect <plik.pcap>
uv run wayside analyze <plik.pcap> --out-dir wayside-out
```

Komenda `analyze` zapisuje w katalogu wyjsciowym `analysis.json` (model
maszynowy) i `report.md` (raport w markdown). Flaga `--pdf` dokladajac
trzeci artefakt, `report.pdf`, z osadzonym fontem Unicode (DejaVu Sans):
w warstwie tekstowej PDF kazdy z osiemnastu polskich znakow diakrytycznych
wystepuje jako pojedynczy, zlozony punkt kodowy, niezaleznie od fontow
zainstalowanych w systemie. Granica tego twierdzenia: to, jak dokument
wyglada w konkretnym czytniku PDF, nie zostalo potwierdzone wzrokowo na
wielu maszynach (`.planning/WINDOWS.md`, pozycje 12 i 13). Flaga jest
domyslnie wylaczona: domyslna sciezka narzedzia nie zyskuje przez to nowej
zaleznosci uruchomieniowej.

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
   w trybie `--no-corpus` na wszystkich sledzonych plikach,
   `git log --all -- standards/.local`, ktory konczy job bledem, gdy wynik
   nie jest pusty, oraz trzeci krok: audyt trzech powierzchni CALEJ historii
   repozytorium (tresc drzew, komunikaty commitow, nazwy plikow) tymi samymi
   wzorcami warstwy tozsamosciowej co bramka biezaca, uruchamiany z jawnym
   wlaczeniem znacznika `slow` pakietu testow.

Ten trzeci krok jest **domyslnie pomijany lokalnie** (znacznik `slow` jest
filtrowany w opcjach domyslnych pakietu testow), bo jego koszt to trzy
powierzchnie razy caly zbior commitow repozytorium - deweloper, ktory nigdy
nie wykonuje publicznego pushu, nigdy go nie uruchamia, i to jest swiadomy
wybor, nie luka. Miejscem, w ktorym ten skan jest obowiazkowy, jest CI oraz
bramka przed publicznym pushem (`compliance/history-audit.md`).

**Czego CI z zalozenia NIE widzi:** lokalnego korpusu `standards/.local` oraz
pliku literalow lokalnych warstwy tozsamosciowej (piata regula,
`identity-local-literal`). Oba sa gitignorowane i nigdy nie trafiaja do
zdalnego repozytorium ani do sekretow CI - to jest architektoniczna
koniecznosc, nie niedopatrzenie: wgranie ktoregos z nich do sekretow
repozytorium zniweczyloby cel warstwy, ktorej bronia. W CI dziala warstwa
strukturalna (regex na odcisk jezyka normatywnego), kontrola sciezki, oraz
cztery reguly ksztaltu warstwy tozsamosciowej - nigdy warstwa korpusowa ani
piata regula, literalna.

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

## Licencja

Wayside jest udostepniony na licencji Apache License, wersja 2.0. Pelna
tresc stoi w pliku [`LICENSE`](LICENSE) w katalogu glownym repozytorium.
Redystrybucja, takze zmodyfikowanej wersji, wymaga zachowania informacji
o prawach autorskich i oznaczenia zmienionych plikow (punkt 4 tresci
licencji). Powod wyboru tej licencji zamiast MIT opisuje rekord decyzji
[`docs/decisions/0007-licencja-apache-2-0.md`](docs/decisions/0007-licencja-apache-2-0.md).
