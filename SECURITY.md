# Polityka bezpieczenstwa

Ten dokument opisuje dwie ROZNE drogi zgloszenia podatnosci, ktore nie sa
wymienne - wybor miedzy nimi nalezy do czytelnika. Dokument opisuje droge
i termin, nie udziela porady prawnej i nie jest zobowiazaniem umownym.

## Podatnosc w narzedziu Wayside

Ta sekcja dotyczy podatnosci w kodzie tego repozytorium, w jego skryptach
i w jego zaleznosciach w postaci, w jakiej repozytorium je przypina - nie
w cudzej instalacji i nie w ruchu, ktory narzedzie analizuje.

Kanal: prywatne zglaszanie podatnosci w zakladce bezpieczenstwa tego
repozytorium (GitHub, karta Security, opcja "Report a vulnerability").
Dlaczego nie ma tu adresu poczty elektronicznej: kanal platformy daje
prywatny watek zgloszenia i sciezke do publikacji ostrzezenia
bezpieczenstwa, a nie wymaga publikowania prywatnego adresu autora.

Potwierdzenie przyjecia zgloszenia: piec dni roboczych. Wstepna ocena
zgloszenia: trzydziesci dni.

**Granice, nazwane wprost, a nie przemilczane:**

- Tu nie stoi zaden termin wydania poprawki. Projekt ma jednego
  utrzymujacego, a obietnica takiego terminu bylaby dokladnie ta klasa
  obietnicy bez pokrycia, ktorej zakazuje PUB-04 - ten plik podlega tej
  samej dyscyplinie co README.
- Tu nie stoi zaden program wynagrodzen za zgloszenie, z tego samego
  powodu.
- Sam ten plik nie wlacza kanalu zgloszeniowego. Prywatne zglaszanie
  podatnosci jest przelacznikiem w ustawieniach repozytorium, niezaleznym
  od tresci tego dokumentu, a jego wlaczenie nalezy do wlasciciela
  repozytorium.

Zglaszajacy dzialajacy w dobrej wierze i w zakresie tej sekcji nie ponosi
z tego tytulu zadnych roszczen ze strony autora.

## Podatnosc znaleziona przy uzyciu Wayside w cudzej sieci

Ta sekcja dotyczy findingu w cudzej instalacji, ustalonego z analizy zrzutu
ruchu przechwyconego przez czytelnika. Autor Wayside nie posredniczy
w takich zgloszeniach i ich nie przyjmuje. Przyjmowanie findingow z cudzej
infrastruktury przemyslowej na prywatne konto jest dokladnie ta klasa
ryzyka, ktora caly ten projekt swiadomie odsuwa.

Zglaszajacy ma trzy wlasne drogi:

1. Wlasciciel systemu - pierwszy i domyslny adresat.
2. Producent albo dostawca urzadzenia.
3. Publiczne punkty koordynacji: CISA ICS-CERT dla podatnosci przemyslowych,
   a dla Polski CSIRT NASK i CSIRT GOV, wlasciwe dla obowiazkow z ustawy
   o krajowym systemie cyberbezpieczenstwa i z dyrektywy o odpornosci
   podmiotow kluczowych.

Termin zgloszenia incydentu narzuca rezim wlasciwy dla czytelnika. Terminy
z sekcji pierwszej go nie dotycza - to jest wlasny termin tej sekcji.

**Granice, nazwane wprost, a nie przemilczane:** co autor moze zrobic -
poprawic narzedzie, jesli finding wynika z bledu narzedzia, a nie
z podatnosci w cudzej sieci. Czego autor nie zrobi - nie skontaktuje sie
z wlascicielem cudzej sieci, nie potwierdzi findingu w cudzej instalacji
i nie przechowa dowodu.
