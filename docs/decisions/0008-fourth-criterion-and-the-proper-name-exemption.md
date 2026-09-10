---
decision_date: 2026-09-09
resolved_option: wyjatek-zawezony-plus-doprecyzowanie-kryterium
---

# 0008: Doprecyzowanie kryterium czwartego fazy publikacji i wyjatek dla nazwy wlasnej

## Kontekst

Kryterium 4 fazy 5 w brzmieniu pierwotnym zada przegladu calej historii
repozytorium pod katem adresacji, nazw urzadzen, sygnatur i nazwy wlasnej
projektu, ktorego repozytorium ten projekt zastapil, "bez trafien". Audyt
trzech powierzchni calej historii (plan `05-04`, zadanie 1) wykryl, ze jedna
z czterech klas wzorcow - nazwa wlasna tamtego projektu - wystepuje
w sledzonym drzewie w piatym miejscu, z powodu, ktorego kryterium
w pierwotnym brzmieniu nie przewidywalo.

Ustalone fakty, zmierzone w tej sesji, zapisane jako ustalenia, nie jako
opinie:

- Wszystkie piec wystapien w sledzonym drzewie to TRESC SAMEGO ZAKAZU:
  tekst wymagania PUB-05 (`REQUIREMENTS.md`), wstep i kryterium 4 fazy 5
  (`ROADMAP.md`), oraz prohibicja przy wymaganiu ASSET-05 w planie fazy 3
  (`03-02-PLAN.md`).
- Zadnego kodu, schematu, adresacji ani sygnatury pochodzacej z tamtego
  projektu w repozytorium nie ma.
- W komunikatach commitow ta nazwa nie wystepuje ani razu - fakt zmierzony
  wprost przebiegiem powierzchni drugiej audytu (`git log --all --format=%B`
  przez cztery reguly ksztaltu warstwy tozsamosciowej), nie zalozony.

## Rozstrzygniecie

Nazwa idzie na jawna liste wyjatkow `.confidentiality-allow`, wyjatkiem
ZAWEZONYM do jednej reguly (`identity-project-name`) i do trzech sciezek
(katalog artefaktow planowania, sam plik listy wyjatkow, sam plik bramki -
wpisy dodane w planie `05-03`). Kryterium 4 fazy 5 zostaje doprecyzowane
fraza o braku trafien POZA jawna lista wyjatkow w `.confidentiality-allow`,
razem z odeslaniem do tego rekordu.

Odrzucona alternatywa: przepisanie historii narzedziem do tego przeznaczonym
(`git filter-repo`). Taka operacja zmienialaby skrot niemal kazdego commita
w repozytorium (piec wystapien wsrod dwustu kilkudziesieciu commitow, ale
przepisanie jednego commita przepisuje skroty wszystkich commitow po nim) -
przez co pola z powolaniami na commity w kazdym pliku SUMMARY dotychczasowych
planow i w `STATE.md` przestalyby wskazywac istniejace obiekty, przy zerowej
wartosci: usuniecie nazwy z tekstu wlasnego zakazu nie usuwa zadnej informacji
o tamtym projekcie, bo zadnej takiej informacji tam nie ma.

## Uzasadnienie

Fakt, ze nazwa wystepuje WYLACZNIE w tresci wlasnego zakazu, jest argumentem
NA KORZYSC autora, nie przeciw niemu - pokazuje, ze granica miedzy dwoma
projektami zostala postawiona swiadomie i zapisana w wymaganiach, zanim
powstala pierwsza linia kodu tego repozytorium. Wyjatek nie ukrywa niczego:
kazde wystapienie jest publicznie czytelne w tekscie wymagania, kryterium
i prohibicji, ktore ten sam wyjatek opisuje.

Zawezenie wyjatku do jednej reguly (nie do calej warstwy tozsamosciowej) jest
celowe: adres z sieci pracodawcy albo nazwa urzadzenia w ktoryms z trzech
wyjetych plikow dalej zapala pozostale cztery reguly tej warstwy. Wyjatek
dotyczy WYLACZNIE nazwy wlasnej, nigdy adresacji ani sygnatur urzadzen.

## Ryzyko rezydualne, nazwane wprost

- Wyjatek jest miejscem, w ktorym bramka SWIADOMIE nie patrzy. Przyszly
  czytelnik listy wyjatkow, ktory nie przeczyta uzasadnienia nad wpisem,
  moze odczytac go jako furtke - dlatego wyjatek jest zawezony do jednej
  reguly i trzech konkretnych sciezek, a nie do calego katalogu planowania
  ani do calej warstwy, i dlatego uzasadnienie nad wpisem mowi to wprost.
- Doprecyzowanie kryterium 4 jest zmiana tekstu, na ktory powoluje sie
  weryfikator fazy - cofniecie tej decyzji wymagaloby ponownego przejscia
  bramki weryfikacyjnej fazy (ocena odwracalnosci: costly, `05-CONTEXT.md`
  D-23).
- Rozstrzygniecie zaklada, ze piec ustalonych wystapien pozostanie
  jedynymi - kazde NOWE wystapienie tej nazwy poza trzema wyjetymi sciezkami
  dalej jest naruszeniem bramki biezacej i audytu historii, bez wzgledu na to
  rozstrzygniecie.

## Konsekwencje dla uzytkownika

Czytelnik repozytorium, ktory przeczyta wymaganie PUB-05, kryterium 4 fazy 5
albo `.confidentiality-allow`, zobaczy nazwe projektu, ktorego to
repozytorium zastapilo, wylacznie w kontekscie wyjasniajacym, dlaczego
granica poufnosci miedzy dwoma projektami zostala postawiona. Nic w tym
repozytorium nie pochodzi z tamtego projektu poza sama jego nazwa uzyta jako
przyklad granicy.

## Sposob egzekwowania

Trzy mechanizmy maszynowe naraz: zawezony wpis `identity-path:identity-project-name:...`
w `.confidentiality-allow` (plan `05-03`); skan trzech powierzchni calej
historii wolajacy te sama regule wyjatkow (plan `05-04`, zadanie 1); oraz
bramka ksztaltu rekordu audytu (`scripts/check_history_audit_gate.py`),
ktora wymaga, zeby pole `rules_checked` rekordu wymienialo dokladnie zbior
regul faktycznie sprawdzonych - rozszerzenie warstwy tozsamosciowej o kolejna
regule wymaga rozszerzenia tej listy w dwoch miejscach naraz, inaczej rekord
twierdzi wiecej, niz skan sprawdzil.

## Droga rewizji

Rozstrzygniecie wymaga ponownego przegladu, gdy zajdzie ktorekolwiek
z ponizszych: audyt trzech powierzchni znajdzie NOWE wystapienie nazwy poza
trzema wyjetymi sciezkami; ktoras z trzech wyjetych sciezek zacznie niesc
tresc INNA niz sam tekst zakazu (kod, schemat, adresacje, sygnature); albo
zapadnie decyzja o przepisaniu historii z innego powodu, co przy okazji
usuwaloby tez te piec wystapien.
