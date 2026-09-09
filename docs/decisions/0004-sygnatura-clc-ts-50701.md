---
decision_date: 2026-09-04
resolved_option: clc-ts-50701-2023
---

# 0004: Sygnatura i edycja dokumentu kolejowego cytowanego obok IEC 62443-3-3

## Kontekst

STD-04 (rejestrze wymagan projektu) stawia dowod wyroznika projektu: dodanie
drugiej normy do katalogu ma byc dopisaniem pliku danych, bez zmiany ani jednej
linii kodu. STD-05 dorzuca warunek, ktory czyni to powolanie weryfikowalnym:
kazde powolanie podaje edycje albo rok normy. Oba wymagania nazywaly ten
dokument `EN 50701` - tak samo nazywaly go ROADMAP (kryterium 4 fazy 4)
i PROJECT.

Ta nazwa byla przyjeta przy tworzeniu wymagan (2026-09-01) i nigdy nie zostala
sprawdzona wobec zrodla. Wlasne badanie projektu widzialo problem juz wczesniej:
badaniu projektowym (funkcje) opisuje ten dokument jako "EN 50701 (formally
CLC/TS 50701, a CENELEC Technical Specification)", a `PITFALLS.md` prowadzi
osobna pulapke numer 13 o mylnym traktowaniu go jako zastepujacego IEC 62443.
Warstwa wymagan tej korekty nie przejela, wiec projekt szedl do fazy 4
z sygnatura, ktorej nie da sie zweryfikowac, bo nie istnieje.

Rejestr ryzyk ROADMAP nazywal to wprost jako pozycje do rozstrzygniecia PRZED
faza 4, nie w jej trakcie. Powod jest ten sam co przy bramce poufnosci z Fazy 1:
bledna sygnatura wpisana do katalogu norm rozchodzi sie potem na kazdy
wygenerowany raport, na nazwe katalogu w drzewie kodu i na kazdy zewnetrzny
opis projektu, a cofniecie tego jest wielokrotnie drozsze niz ustalenie nazwy
raz, zanim powstanie pierwszy plik.

## Rozstrzygniecie

Wybrana opcja: `CLC/TS 50701:2023`.

Ustalenia potwierdzone u zrodla (CEN-CENELEC) i u dwoch niezaleznych
dystrybutorow norm:

- Normy `EN 50701` nie ma. Dokument jest specyfikacja techniczna CENELEC
  (Technical Specification), nie norma europejska, i jego wlasna sygnatura to
  `CLC/TS 50701`. Roznica nie jest kosmetyczna: TS jest dokumentem
  tymczasowym o slabszym statusie normatywnym niz EN.
- Edycja druga zostala opublikowana w sierpniu 2023 i zastapila pierwsza
  z lipca 2021. Powolania podaja rok 2023.
- Tresc idzie docelowo do przyszlej normy IEC 63452, opracowywanej wspolnie
  przez CENELEC i IEC. Ta norma jeszcze nie istnieje, wiec nie dotyczy v1.

Odrzucone alternatywy: `EN 50701` bez roku (odrzucona, bo cytuje dokument,
ktory nie istnieje, i lamie STD-05 przez brak edycji); `CLC/TS 50701` bez roku
(odrzucona, bo dwie edycje roznia sie trescia, a powolanie bez roku nie da sie
zweryfikowac wobec egzemplarza - dokladnie ten tryb porazki, ktory STD-05
mial zamknac); `IEC 63452` (odrzucona, bo dokument nie jest opublikowany).

## Uzasadnienie

To rozstrzygniecie nie jest kwestia gustu redakcyjnego. Odbiorca tego projektu
to recenzent z sektora kolejowego, a powolanie na nieistniejaca sygnature normy
w narzedziu, ktorego cala obietnica brzmi "kazdy finding stoi na punkcie normy",
podwaza obietnice mocniej niz brak drugiej normy w ogole. Podanie statusu TS
zamiast EN ma tez konsekwencje merytoryczna: TS jest dokumentem stosowanym
dobrowolnie, wiec raport nie moze go przedstawiac jako podstawy obowiazkowej.

## Ryzyko rezydualne, nazwane wprost

Ta decyzja rozstrzyga WYLACZNIE sygnature, status i edycje dokumentu.
NIE rozstrzyga dostepu do jego tresci: numeracja i tresc konkretnych punktow
pozostaja niezweryfikowane wobec legalnego egzemplarza, bo egzemplarza projekt
nie ma. To osobne, wciaz otwarte ryzyko fazy 4, prowadzone w rejestrze ryzyk
ROADMAP jako "Legalny dostep do IEC 62443-3-3 i CLC/TS 50701".

Wprost: sygnatura jest teraz poprawna, a punkty pod nia nie sa jeszcze
potwierdzone. Znacznik `verified` w katalogu norm istnieje wlasnie po to,
zeby ta roznica byla widoczna w danych, nie tylko w tym rekordzie.

## Konsekwencje dla uzytkownika

Kazde powolanie na dokument kolejowy w wygenerowanym raporcie brzmi
`CLC/TS 50701:2023`. Czytelnik, ktory chce sprawdzic powolanie, ma pelna
sygnature razem z edycja, wiec kupuje albo otwiera dokladnie ten dokument,
o ktory chodzi. Katalog norm dostaje osobny katalog danych dla tego dokumentu;
jego nazwa idzie od sygnatury, nie od nazwy `en50701` proponowanej wczesniej
w badaniu projektowym (architektura).

## Sposob egzekwowania

Bramka maszynowa dla tego rozstrzygniecia NIE ISTNIEJE w chwili zapisu tego
rekordu - powstaje razem z planem fazy 4, ktory dowozi STD-04 i STD-05.
Plan fazy 4 ma dolozyc test czytajacy pole `resolved_option` z frontmatteru
tego rekordu i sprawdzajacy, ze zadne powolanie w katalogu norm ani w
wygenerowanym raporcie nie uzywa ciagu `EN 50701`, oraz ze kazde powolanie
na ten dokument nosi rok edycji. Do momentu, w ktorym ten test istnieje,
sygnatury pilnuje ten rekord i konwencja, nie maszyna.

## Droga rewizji

Publikacja IEC 63452 jest zdarzeniem, ktore wymusza rewizje: powolania
zaczna wtedy wskazywac norme miedzynarodowa, a `CLC/TS 50701:2023` przejdzie
w pozycje historyczna. Rewizja polega na aktualizacji tego rekordu z nowa data
i nowym `resolved_option` oraz na dopisaniu nowego pliku katalogu norm - nie na
zmianie kodu, dokladnie zgodnie z STD-04. Publikacja trzeciej edycji
`CLC/TS 50701` domyka sie tak samo.
