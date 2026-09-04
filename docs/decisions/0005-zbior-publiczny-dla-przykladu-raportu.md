---
decision_date: 2026-09-04
resolved_option: 4sics-skrypt-pobierajacy
---

# 0005: Zbior publiczny, z ktorego powstaje przykladowy raport

## Kontekst

REPORT-05 (`.planning/REQUIREMENTS.md`) wymaga, zeby w repozytorium lezal
przykladowy raport wygenerowany z publicznego zbioru danych, odtwarzalny
z tego zbioru bajtowo identycznie. To nie jest wymaganie kosmetyczne:
notatki projektu nazywaja ten raport glownym artefaktem promocyjnym,
mocniejszym nosnikiem niz samo repozytorium, bo wniosek czyta sie sam,
a postep prac nie.

Roadmapa stawiala na zbior ELECTRA i nazywala jego dostepnosc ryzykiem
do rozstrzygniecia przed faza 4. Powod preferencji byl dziedzinowy: ELECTRA
modeluje system sterowania podstacji trakcyjnej kolei duzych predkosci
i niesie Modbus oraz S7Comm, wiec daje przykladowi raportu wartosc
w dokladnie tym sektorze, w ktorym projekt ma byc czytany. Zbior byl
potwierdzony jako istniejacy i kolejowy, ale nie jako publicznie pobieralny.

## Rozstrzygniecie

Wybrana opcja: podzbior 4SICS od Netresec, do repozytorium wchodzi skrypt
pobierajacy plus wygenerowany raport, nigdy sam plik pcap.

Ustalenia potwierdzone w badaniu:

- ELECTRA jest opisana w literaturze naukowej, ale publicznego punktu
  pobrania nie ma. Dostep prowadzi przez kontakt z autorami zbioru, czego
  wymaganie odtwarzalnosci w REPORT-05 nie moze zalozyc: czytelnik
  repozytorium ma odtworzyc raport sam, bez korespondencji z nikim.
- 4SICS (Netresec, ruch z wioski ICS konferencji) jest pobieralny publicznie
  i wazy okolo 360 MB.
- Warunki redystrybucji 4SICS sa jawne i lagodne: atrybucja dla CS3Sthlm za
  udostepnienie ruchu z laboratorium, plus odeslanie do strony Netresec.
  Redystrybucja jest wiec dozwolona, takze w materialach szkoleniowych.

Odrzucone alternatywy: ELECTRA jako droga podstawowa (odrzucona z powodu
braku publicznego punktu pobrania - lamie odtwarzalnosc); commit plikow pcap
4SICS do repozytorium, na ktory licencja by pozwalala (odrzucony z powodu
rozmiaru: 360 MB w kazdym klonie za jeden przykladowy raport to zla wymiana,
a osobno kazdy commit danych osob trzecich do repozytorium, ktore ma byc
publiczne, jest w praktyce nieodwracalny - ten sam koszt, ktory rozstrzygniecie
0002 nazywa dla tabeli OUI).

## Uzasadnienie

Odtwarzalnosc bije wartosc dziedzinowa. Raport z ruchu laboratorium ICS jest
slabszy tematycznie od raportu z podstacji trakcyjnej, ale raport, ktorego
czytelnik nie moze odtworzyc, nie dowodzi niczego - a REPORT-05 stawia
odtwarzalnosc bajtowa jako warunek, nie jako mile dodatek. Skrypt pobierajacy
zamiast kopii pcap trzyma repozytorium male i omija cala klase pytan
o redystrybucje, mimo ze licencja 4SICS by na nia pozwalala.

## Ryzyko rezydualne, nazwane wprost

- Przyklad raportu traci kolejowa wartosc dziedzinowa. Ruch z wioski ICS
  konferencji to nadal prawdziwy ruch przemyslowy, ale nie jest ruchem
  kolejowym, wiec raport nie pokazuje tego sektora, w ktorym projekt ma
  swoj wyroznik. Nie da sie tego nadrobic dobraniem checkow.
- Odtwarzalnosc bajtowa zalezy od tego, ze pliki pod adresami Netresec nie
  zmieniaja sie. Skrypt pobierajacy ma zapisywac sume kontrolna pobranego
  pliku, zeby cicha podmiana u zrodla zostala wykryta jako blad, a nie jako
  rozjazd raportu.
- Atrybucja dla CS3Sthlm jest warunkiem licencyjnym, wiec jej brak w README
  albo w samym raporcie jest naruszeniem, nie niedbalstwem redakcyjnym.

## Konsekwencje dla uzytkownika

Czytelnik repozytorium widzi gotowy przykladowy raport bez pobierania
czegokolwiek, a jesli chce sprawdzic, czy raport faktycznie z tego zbioru
powstal, uruchamia skrypt pobierajacy i powtarza generowanie. Klon
repozytorium nie rosnie o rozmiar zbioru.

## Sposob egzekwowania

Bramka maszynowa dla tego rozstrzygniecia NIE ISTNIEJE w chwili zapisu tego
rekordu - powstaje razem z planem fazy 4, ktory dowozi REPORT-05. Plan fazy 4
ma dolozyc wpis w manifescie fixture'ow ze zrodlem i licencja zbioru
(wymog FOUND-05, ktory juz dziala i ma swoj test), test odtwarzalnosci
porownujacy wygenerowany raport z zapisanym, oraz test na brak plikow pcap
tego zbioru w drzewie sledzonym przez git.

## Droga rewizji

Pojawienie sie publicznego punktu pobrania dla ELECTRA albo dla innego
zbioru z ruchem kolejowym zamyka ryzyko rezydualne nazwane wyzej. Rewizja
polega na aktualizacji tego rekordu z nowa data i nowym `resolved_option`,
podmianie adresu w skrypcie pobierajacym i ponownym wygenerowaniu raportu -
kod potoku sie nie zmienia, bo zbior jest dla niego wejsciem, nie zaleznoscia.
