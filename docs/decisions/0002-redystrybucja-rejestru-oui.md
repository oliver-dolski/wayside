---
decision_date: 2026-09-04
resolved_option: commit-pelnej-tabeli
---

# 0002: Redystrybucja rejestru IEEE OUI w tym repozytorium

## Kontekst

ASSET-02 (`.planning/REQUIREMENTS.md`) wymaga ustalania producenta urzadzenia
z prefiksu adresu MAC wobec tabeli wyprowadzonej z rejestru IEEE OUI. Ta sama
sekcja `REQUIREMENTS.md`, w bloku "Out of Scope", odrzuca plik `manuf`
Wiresharka jako zrodlo tych danych z uzasadnieniem: plik `manuf` jest
pochodna GPLv2 i zatruwa licencyjnie publiczne repozytorium, podczas gdy
rejestr IEEE jest w domenie publicznej. Drugie zdanie tego uzasadnienia jest
ZALOZENIEM PROJEKTU zapisanym przy tworzeniu wymagan (2026-09-01), nie
faktem zweryfikowanym wobec zrodla prawnego.

Badanie fazy (`03-RESEARCH.md`, Pattern 6, Assumption A4, Open Question 2)
sprawdzilo to zalozenie w tej sesji: strona IEEE Registration Authority
(`standards.ieee.org/products-programs/regauth/`) nie podaje wprost
warunkow redystrybucji danych rejestru OUI. Jedyna wzmianka prawna znaleziona
na tej stronie jest ogolna nota o zastrzezeniu praw autorskich w stopce, bez
osobnego dokumentu licencji ani warunkow uzycia dla samej listy przydzialow.
Praktyka calej branzy narzedziowej (Wireshark, nmap, arp-scan,
`mac-vendor-lookup`) redystrybuuje te sama liste bez osobnej licencji od
IEEE - to jest silny sygnal branzowy, ale nie jest dowodem prawnym. Badanie
nie znalazlo tez zadnego precedensu przeciwnego (zadania od IEEE
o usuniecie takiej redystrybucji), ale brak znalezionego precedensu nie
jest tym samym co jego brak w rzeczywistosci.

Repozytorium ma stac sie publiczne: bramka PUB-01
(`compliance/pre-publication-review.md`) rozstrzygnela na `go` dnia
2026-09-02. Commit danych osob trzecich do drzewa, ktore ma trafic do
publicznego hostingu, jest w praktyce nieodwracalny - usuniecie po fakcie
wymaga przepisania historii gita i uniewaznienia kazdego istniejacego klona.
To jest ten sam rodzaj kosztu, dla ktorego bramka poufnosci norm z Fazy 1
stoi PRZED pierwszym plikiem katalogu norm, a nie po nim - to powod, dla
ktorego to rozstrzygniecie zaslugiwalo na osobny checkpoint blokujacy czlowieka
(`03-05-PLAN.md`, Task 3, `gate="blocking-human"`), a nie na cichy wybor
implementacyjny.

## Rozstrzygniecie

Wybrana opcja: pelna tabela wyprowadzona z rejestru IEEE OUI, zacommitowana
do repozytorium pod `src/wayside/assets/oui_table.tsv`.

Odrzucone alternatywy: podzbior rejestru ograniczony do producentow z
dziedziny sterowania przemyslowego (odrzucony, bo recznie utrzymywana lista
pomijalaby producenta mozliwego do ustalenia, a inwentarz milczalby o nim
zamiast nazwac ograniczenie - narzedzie oceny bezpieczenstwa liczy sie
z kompletnoscia bardziej niz z rozmiarem pliku); zero danych osob trzecich
w repozytorium, tabela budowana lokalnie przez uzytkownika (odrzucony, bo
swiezy klon bez dostepu do sieci nie ustala wtedy producenta dla zadnego
hosta, co lamie obietnice pracy w sieci odcietej z FOUND-01 dokladnie
w momencie, w ktorym narzedzie ma dzialac samodzielnie).

## Uzasadnienie

Narzedzie dziala po klonie bez zadnego dodatkowego kroku i bez dostepu do
sieci - dokladnie tak, jak obiecuje FOUND-01. Pominiecie producenta spoza
recznie utrzymywanej listy jest gorszym trybem porazki dla narzedzia oceny
bezpieczenstwa niz kilka megabajtow tekstu w repozytorium: cichy brak
wpisu wyglada jak "nic tu nie ma", nie jak "wiedziano, ze tego nie da sie
ustalic". Wybor jest zgodny z rekomendacja badania fazy i z ustalona
praktyka calej branzy narzedziowej redystrybuujacej te sama liste.

## Ryzyko rezydualne, nazwane wprost

Ta decyzja NIE rozstrzyga statusu prawnego rejestru IEEE OUI - rozstrzyga
wylacznie to, ze projekt idzie dalej przy zalozeniu praktyki branzowej,
swiadomie akceptujac nastepujace ryzyko:

- Warunki redystrybucji danych rejestru IEEE OUI nie zostaly potwierdzone
  wobec zadnego zrodla prawnego - ani przez to badanie, ani wczesniej przez
  `REQUIREMENTS.md`, ktory przyjal "domene publiczna" jako zalozenie w chwili
  odrzucania pliku `manuf`. Jesli to zalozenie okaze sie bledne, ryzyko
  dotyczy calej branzy narzedziowej rownolegle, nie tylko tego projektu, ale
  to NIE jest ekspertyza prawna i nie zastepuje jej.
- Plik `oui_table.tsv` wazy rzedu kilkudziesieciu tysiecy wierszy i trafia do
  kazdego klona repozytorium od tego commita w przod.
- Wycofanie tej decyzji po upublicznieniu repozytorium (PUB-01, `go`,
  2026-09-02) wymaga przepisania historii gita i uniewaznienia kazdego
  istniejacego klona - to nie jest zmiana odwracalna zwyklym commitem
  odwrotnym.

## Konsekwencje dla uzytkownika

Swiezy klon repozytorium ustala producenta dla kazdego hosta o adresie MAC
uniwersalnie administrowanym, obecnym w rejestrze, bez zadnego dodatkowego
kroku i bez dostepu do sieci. Fixture'y tego projektu uzywaja adresow MAC
lokalnie administrowanych (prefiks `02:`, poza zakresem rejestru IEEE
z definicji), wiec pole producenta pozostaje `not-derivable-passively`
w kazdym przebiegu na fixture'ach testowych - to jest wynik poprawny, nie
usterka generatora ani tabeli.

## Sposob egzekwowania

`tests/test_oui.py::test_decision_record_resolved_option_matches_tree_state`
czyta pole `resolved_option` z frontmatteru tego rekordu i sprawdza, ze
obecnosc `src/wayside/assets/oui_table.tsv` w drzewie sledzonym przez git
odpowiada temu rozstrzygnieciu - zmiana jednego bez drugiego przerywa
bramke testowa. Osobno, `tests/test_oui.py` zawiera dwie bramki niezalezne
od tej decyzji: brak pliku `manuf` Wiresharka w calym drzewie repozytorium
i brak importu sieciowego w `src/wayside/`.

## Droga rewizji

Rewizja tej decyzji w kierunku ostrozniejszym (usuniecie tabeli z
repozytorium) wymaga aktualizacji tego rekordu z nowa data i nowym
rozstrzygnieciem w polu `resolved_option`, przepisania historii gita, zeby
plik faktycznie zniknal z kazdego wczesniejszego commita, oraz komunikatu do
kazdego, kto juz sklonowal repozytorium. Potwierdzenie statusu prawnego
rejestru IEEE OUI wobec faktycznego zrodla prawnego (nie samej praktyki
branzowej) zamknieloby ryzyko rezydualne nazwane wyzej bez koniecznosci
takiej rewizji.
