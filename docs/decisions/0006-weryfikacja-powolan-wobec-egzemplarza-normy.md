---
decision_date: 2026-09-04
resolved_option: kupno-tylko-iec62443-3-3
---

# 0006: Ktore powolania sa weryfikowane wobec legalnego egzemplarza normy

## Kontekst

STD-03 (`.planning/REQUIREMENTS.md`) wymaga, zeby kazdy finding mial powolanie
na punkt IEC 62443-3-3. STD-05 dorzuca warunek weryfikowalnosci: kazde
powolanie podaje edycje albo rok normy. Oba wymagania trzymaja sie tylko
wtedy, gdy numeracja i tresc cytowanych punktow zostaly sprawdzone wobec
legalnego egzemplarza dokumentu - inaczej narzedzie podaje numer punktu,
ktorego nikt nie widzial, jako fakt.

Oba dokumenty sa platne. Egzemplarze pracodawcy nie sa wlasciwa podstawa,
bo projekt jest prywatny i ma byc publiczny (PUB-01 rozstrzygnieta na `go`,
2026-09-02). Rejestr ryzyk ROADMAP nazywal ten dostep jako pozycje do
rozstrzygniecia przed faza 4.

Ceny ustalone 2026-09-04:

- IEC 62443-3-3, edycja pierwsza z 2013, w IEC Webstore: CHF 380.
- Ten sam dokument w wersji ISA (ANSI/ISA-62443-3-3-2013): 403 USD, czyli
  droga przez IEC jest tansza.
- CLC/TS 50701:2023 przez krajowa jednostke normalizacyjna: rzad kilkuset
  euro. Dokladnej ceny w PKN nie ustalono, bo sklep nie przechodzi
  weryfikacji certyfikatu przez narzedzie pobierajace.

Sygnatura i edycja dokumentu kolejowego sa rozstrzygniete osobno - rekord
`0004`. Ten rekord dotyczy wylacznie dostepu do TRESCI.

## Rozstrzygniecie

Wybrana opcja (Oliver, 2026-09-04): kupno jednego egzemplarza,
IEC 62443-3-3. Powolania na CLC/TS 50701:2023 wchodza do v1 z jawnym
znacznikiem `verified: no`.

Podzial obowiazuje wiec tak:

- IEC 62443-3-3 - numeracja i tresc punktow weryfikowane wobec kupionego
  egzemplarza, docelowo `verified: yes`.
- CLC/TS 50701:2023 - sygnatura i edycja potwierdzone u zrodla (rekord
  `0004`), numeracja punktow niepotwierdzona, `verified: no` widoczne
  w katalogu, w raporcie i w README.

Odrzucone alternatywy: kupno obu egzemplarzy (okolo 3300 PLN - odrzucone,
bo w fazie 4 rola dokumentu kolejowego jest architektoniczna, patrz
uzasadnienie); zero zakupow (odrzucone, bo STD-03 stawia IEC 62443-3-3 pod
KAZDYM findingiem v1, a nie pod czescia).

## Uzasadnienie

Te dwa dokumenty nie niosa w fazie 4 tego samego ciezaru.

IEC 62443-3-3 stoi pod kazdym findingiem, jaki narzedzie produkuje.
Niezweryfikowany numer punktu w tym miejscu podkopuje glowna obietnice
projektu ("kazdy finding stoi na punkcie normy") w kazdym pojedynczym
wierszu raportu, a nie na jego marginesie. Tu weryfikacja jest warta swojej
ceny.

Rola CLC/TS 50701 w fazie 4 jest architektoniczna. Kryterium 4 tej fazy
dowodzi, ze DRUGA norma wchodzi do katalogu jako plik danych, przy zerowym
diffie na plikach `.py`. To twierdzenie o architekturze i jest prawdziwe
niezaleznie od tego, czy punkty tej normy zostaly potwierdzone wobec
egzemplarza. Znacznik `verified` istnieje w katalogu wlasnie po to, zeby
roznica miedzy "sprawdzone" i "niesprawdzone" byla widoczna w danych; jego
podniesienie po pozniejszym zakupie jest edycja pliku YAML, nie zmiana kodu -
dokladnie ta wlasnosc, ktorej dowodzi kryterium 4.

## Ryzyko rezydualne, nazwane wprost

- Zakup IEC 62443-3-3 NIE MIAL jeszcze miejsca w chwili zapisu tego rekordu.
  Do momentu, w ktorym egzemplarz jest w rekach autora i punkty zostaly
  wobec niego przeczytane, powolania na IEC 62443-3-3 pozostaja
  `verified: no` tak samo jak kolejowe. Ten rekord rozstrzyga zamiar
  i podzial, nie stan.
- Wyroznik projektu w kolejnictwie wchodzi do v1 czesciowo
  niezweryfikowany. Recenzent z sektora kolejowego, ktory zna
  CLC/TS 50701, zobaczy numer punktu ze znacznikiem `verified: no`.
  To jest uczciwe i zamierzone, ale slabsze niz powolanie potwierdzone.
- Znacznik `verified: no` musi byc widoczny w KAZDYM miejscu, gdzie
  powolanie sie pojawia, nie tylko w pliku katalogu. Powolanie, ktore
  w raporcie wyglada jak pewne, a w katalogu ma `verified: no`, jest
  gorszym trybem porazki niz brak drugiej normy w ogole.

## Konsekwencje dla uzytkownika

Raport podaje przy kazdym powolaniu, czy punkt zostal sprawdzony wobec
egzemplarza normy. README nazywa ten stan wprost, razem z powodem
(dokumenty sa platne) i z droga podniesienia znacznika. Czytelnik wie,
ktoremu powolaniu moze zaufac bez wlasnej weryfikacji, a ktore ma sprawdzic
u siebie.

## Sposob egzekwowania

Bramka maszynowa dla tego rozstrzygniecia NIE ISTNIEJE w chwili zapisu tego
rekordu - powstaje razem z planem fazy 4. Plan fazy 4 ma dolozyc: test
odrzucajacy powolanie bez pola `verified`, test sprawdzajacy, ze wpis
`verified: no` przenosi sie do wygenerowanego raportu jako widoczne
zastrzezenie (a nie tylko do `analysis.json`), oraz zapis w README
opisujacy ten stan. Weryfikacja numeracji punktow IEC 62443-3-3 wobec
kupionego egzemplarza jest zadaniem dla czlowieka, wiec plan stawia ja jako
checkpoint blokujacy - wykonawca nie moze podniesc znacznika `verified`
wlasna ocena, bo egzemplarza nie widzi.

## Droga rewizji

Zakup CLC/TS 50701:2023 w dowolnym pozniejszym momencie zamyka ryzyko
rezydualne nazwane wyzej: rewizja polega na aktualizacji tego rekordu
z nowa data i nowym `resolved_option`, przeczytaniu punktow wobec
egzemplarza i podniesieniu pola `verified` w pliku katalogu. Kod potoku sie
nie zmienia. Rezygnacja z zakupu IEC 62443-3-3 domyka sie tak samo
w przeciwna strone, ale zostawia wtedy calosc powolan v1 niezweryfikowana
i README musi to nazwac.
