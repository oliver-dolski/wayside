---
decision_date: 2026-09-09
resolved_option: apache-2-0
---

# 0007: Wybor licencji Apache License 2.0 dla publicznego repozytorium

## Kontekst

Repozytorium przechodzi ze stanu prywatnego warsztatu w stan gotowy do
publicznego wystawienia (faza 5, `05-CONTEXT.md` D-02). Bez pliku licencji
publiczny kod jest formalnie "wszelkie prawa zastrzezone" w calosci - nikt
poza autorem nie ma prawa go uzyc, kopiowac ani modyfikowac, niezaleznie od
tego, co mowi dokumentacja.

To jest sprzecznosc wewnatrz jednego dokumentu, nie brakujaca zdolnosc.
Sekcja `## Intended Use` dowieziona przez plan `05-01` tej samej fazy
opisuje wprost, do czego narzedzie jest przeznaczone (ocena bezpieczenstwa,
material do raportu dla wlasciciela systemu) i zaprasza czytelnika do
uzycia go w tym celu. Brak pliku `LICENSE` zaprzeczalby tej sekcji w
momencie, w ktorym ktokolwiek probowalby skorzystac z zaproszenia.

## Rozstrzygniecie

Wybrana opcja (Oliver, ustalenie fazy 5, D-02): **Apache License,
wersja 2.0**, z naglowkiem praw autorskich `Copyright 2026 Oliver Dolski`
w bloku koncowym tekstu.

Odrzucona alternatywa: **MIT** - licencja permisywna bez jawnego udzielenia
patentowego. Odrzucona, bo milczy dokladnie tam, gdzie odbiorca docelowy
z `PROJECT.md` (integratorzy automatyki i dostawcy uslug zarzadzanych,
uzycie komercyjne w sektorze OT/ICS) potrzebuje jawnosci: MIT nie zawiera
zadnego postanowienia o patentach, wiec ani nie udziela licencji
patentowej, ani nie chroni odbiorcy przed pozniejszym roszczeniem
patentowym ze strony wspolautora.

## Uzasadnienie

Apache License 2.0 niesie w punkcie 3 ("Grant of Patent License") jawne,
nieodwolywalne udzielenie licencji patentowej od kazdego wspolautora
kazdemu odbiorcy, z klauzula wygasniecia przy zlozeniu pozwu patentowego
przeciwko Wayside. Odbiorca docelowy tego projektu - integrator wdrazajacy
narzedzie w srodowisku klienta, dostawca uslugi zarzadzanej budujacy na nim
oferte komercyjna - ma z tego powodu wieksza pewnosc prawna niz przy MIT,
gdzie kwestia patentow nie jest poruszona w ogole.

## Ryzyko rezydualne, nazwane wprost

- Udzielenie licencji publicznej jest **jednokierunkowe**: wobec kogokolwiek,
  kto juz pobral kod pod ta licencja, cofniecie nie dziala. Zmiana licencji
  w przyszlosci obowiazywalaby wylacznie na przyszlosc, nie retroaktywnie.
- Apache 2.0 niesie dluzszy tekst (202 linie tekstu kanonicznego) i wiecej
  formalnych wymogow atrybucji niz MIT - punkt 4 wymaga zachowania
  wszystkich informacji o prawach autorskich, patentach, znakach
  towarowych i atrybucji z formy zrodlowej, oraz oznaczenia zmienionych
  plikow. Odbiorca redystrybuujacy zmodyfikowana wersje musi spelnic te
  wymogi; MIT wymaga mniej.
- Wybor tej wlasnie licencji jest decyzja jednorazowa co do tresci: zmiana
  licencji projektu w przyszlosci (np. na inna licencje permisywna) jest
  mozliwa wobec nowych wydan, ale nie usuwa praw juz udzielonych do
  istniejacych kopii kodu.

## Konsekwencje dla uzytkownika

Co wolno: uzycie komercyjne i niekomercyjne, modyfikacja, dystrybucja
i sublicencjonowanie Wayside oraz utworow pochodnych, bez obowiazku
udostepnienia zmodyfikowanego kodu zrodlowego (licencja permisywna, nie
copyleft).

Czego wymaga atrybucja: kazda dystrybucja (takze zmodyfikowanej wersji)
musi zachowac tresc pliku `LICENSE`, informacje o prawach autorskich
i patentach z formy zrodlowej Wayside, oraz jasno oznaczyc pliki zmienione
wzgledem oryginalu. Szczegoly stoja w punkcie 4 tresci licencji.

## Sposob egzekwowania

Bramka maszynowa `tests/test_license.py` sprawdza, ze tresc pliku
`LICENSE` rozni sie od tekstu kanonicznego dokladnie jedna linia (wiersz
praw autorskich), porownaniem skrotu sha256 po podstawieniu wiersza
wzorcowego z powrotem, oraz obecnoscia kazdego z dziewieciu numerowanych
punktow. Naglowek `## Licencja` w `README.md` ma wlasny wpis
w `compliance/readme-claims.yaml`, wiec bramka `tests/test_readme_claims.py`
pilnuje, zeby ten naglowek zawsze niosl obietnice pokryta dowodem.

Potwierdzenie D-03: nazwa projektu "Wayside" zostaje bez zmiany - przeglad
przed pierwszym publicznym pushem sie odbyl (rewizja przewidziana
w `PROJECT.md`), a jego wynik jest negatywny wobec zmiany. `tests/test_license.py`
sprawdza pole nazwy pakietu i wpis komendy wiersza polecen w
`pyproject.toml` wobec tego rozstrzygniecia, zeby przyszla cicha zmiana
nazwy zaczerwienila bramke zamiast przejsc niezauwazona.

## Droga rewizji

Rozstrzygniecie wymaga ponownego przegladu, gdy zajdzie ktorekolwiek
z ponizszych: model biznesowy projektu przesunie sie w strone, ktorej
Apache 2.0 nie obsluguje dobrze (np. potrzeba licencji copyleft, zeby
wymusic udostepnianie modyfikacji), partner komercyjny zazada innej
licencji jako warunku wspolpracy, albo pojawi sie roszczenie patentowe
wymagajace ponownej oceny klauzuli wygasniecia z punktu 3. Rewizja polega
na wydaniu nowej wersji pod nowa licencja - zmiana obowiazuje **wylacznie
na przyszlosc**, kopie juz rozpowszechnione pod Apache 2.0 zachowuja to
udzielenie bezterminowo.
