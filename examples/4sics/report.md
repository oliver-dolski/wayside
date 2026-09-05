# Raport Wayside

Wygenerowano: 2026-09-04T00:00:00+00:00

## Streszczenie

Analiza zrzutu `4sics-slice.pcap` wykazala 5 finding(i) wymagajacy(ych) uwagi.

## Zakres

Zrzut niesie 40 pakietow. W tym zrzucie rozpoznano protokol(y): modbus-tcp, rozpoznawane po ksztalcie zawartosci segmentu, nigdy po numerze portu. Ruch, ktorego protokolu nie rozpoznano, ma wiersz w macierzy komunikacji z etykieta `tcp` i nie jest podstawa zadnego findingu.
Okno czasowe zrzutu: od 1445499126.04817 do 1445499126.8009 (znaczniki czasu epoki Unix). Snaplen odczytany z naglowka zrzutu: 65535 bajtow. Ramek ucietych przez snaplen: 0. Zdarzen rozpoznanych z niska pewnoscia: 0.

## Metodyka

Kazdy finding niesie wskaznik zaobserwowanego zachowania w ruchu sieciowym, nigdy ocene, czy instalacja spelnia albo nie spelnia wymagan normy. Waga findingu wynika z ponizszych, udokumentowanych kryteriow rubryki (wersja 1.0), nie z wymyslonej skali:

- **low**: Obserwacja o niewielkim wplywie na bezpieczenstwo, bez bezposredniej sciezki do zaklocenia dzialania procesu.
- **medium**: Odstepstwo od dobrej praktyki, ktore w polaczeniu z innym warunkiem moze prowadzic do zaklocenia dzialania procesu.
- **high**: Operacja, ktora sama w sobie pozwala wplynac na stan procesu bez uwierzytelnienia ani autoryzacji nadawcy.
- **critical**: Warunek umozliwiajacy natychmiastowa i bezposrednia ingerencje w bezpieczenstwo procesu, bez zadnych dodatkowych warunkow.

## Inwentarz

### 10.10.10.20

- ip: 10.10.10.20 (observed)
- mac: 00:1c:06:27:64:11 (observed)
- Producent: Siemens Numerical Control Ltd., Nanjing (inferred:oui-lookup)
- Podadresy Unit ID: nieustalone (not-derivable-passively)
- Brama: nieustalone (not-derivable-passively)
- Rola: nieustalona (not-derivable-passively)
- Dowod roli: Zero zdarzen Modbus powiazanych z tym adresem w tym zrzucie (zadania wyslane: 0, zadania odebrane: 0). (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

### 10.10.10.10

- ip: 10.10.10.10 (observed)
- mac: 28:63:36:89:59:82 (observed)
- Producent: Siemens AG (inferred:oui-lookup)
- Podadresy Unit ID: nieustalone (not-derivable-passively)
- Brama: nieustalone (not-derivable-passively)
- Rola: nieustalona (not-derivable-passively)
- Dowod roli: Zero zdarzen Modbus powiazanych z tym adresem w tym zrzucie (zadania wyslane: 0, zadania odebrane: 0). (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

### 192.168.88.50

- ip: 192.168.88.50 (observed)
- mac: 00:05:e4:01:24:d3 (observed)
- Producent: Red Lion Controls Inc. (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowod roli: Zadania Modbus wyslane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

### 192.168.2.44

- ip: 192.168.2.44 (observed)
- mac: 00:07:7c:1a:61:83 (observed)
- Producent: Westermo Network Technologies AB (inferred:oui-lookup)
- Podadresy Unit ID: nieustalone (not-derivable-passively)
- Brama: nieustalone (not-derivable-passively)
- Rola: klient Modbus (inferred:modbus-traffic-direction)
- Dowod roli: Zadania Modbus wyslane przez ten adres: 5; zadania Modbus odebrane przez ten adres: 0. (observed)
- Pewnosc roli: srednia (inferred:event-count-and-direction)

### 192.168.88.100

- ip: 192.168.88.100 (observed)
- mac: 00:e0:62:40:57:66 (observed)
- Producent: HOST ENGINEERING (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowod roli: Zadania Modbus wyslane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

### 192.168.88.20

- ip: 192.168.88.20 (observed)
- mac: 00:a0:45:6f:4b:83 (observed)
- Producent: Phoenix Contact GmbH & Co. KG (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowod roli: Zadania Modbus wyslane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

### 192.168.88.60

- ip: 192.168.88.60 (observed)
- mac: 00:90:e8:26:40:23 (observed)
- Producent: MOXA TECHNOLOGIES CORP., LTD. (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowod roli: Zadania Modbus wyslane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

### 192.168.88.61

- ip: 192.168.88.61 (observed)
- mac: 00:90:e8:27:8c:37 (observed)
- Producent: MOXA TECHNOLOGIES CORP., LTD. (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowod roli: Zadania Modbus wyslane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewnosc roli: niska (inferred:event-count-and-direction)

## Macierz komunikacji

| Sesja | Zrodlo | Cel | Kierunek | Protokol | Wolumen (B) | Pakietow | Strona inicjujaca |
|---|---|---|---|---|---|---|---|
| 0 | 10.10.10.20:49156 | 10.10.10.10:102 | 10.10.10.20:49156 -> 10.10.10.10:102 (inferred:first-observed-sender) | tcp | 634 | 6 | nieustalona (not-derivable-passively) |
| 1 | 192.168.2.44:58597 | 192.168.88.50:502 | 192.168.2.44:58597 -> 192.168.88.50:502 (observed) | modbus-tcp | 260 | 4 | 192.168.2.44:58597 (observed) |
| 2 | 192.168.2.44:58601 | 192.168.88.100:502 | 192.168.2.44:58601 -> 192.168.88.100:502 (observed) | modbus-tcp | 320 | 5 | 192.168.2.44:58601 (observed) |
| 3 | 192.168.2.44:58599 | 192.168.88.20:502 | 192.168.2.44:58599 -> 192.168.88.20:502 (observed) | modbus-tcp | 260 | 4 | 192.168.2.44:58599 (observed) |
| 4 | 192.168.2.44:58598 | 192.168.88.60:44818 | 192.168.2.44:58598 -> 192.168.88.60:44818 (observed) | tcp | 308 | 4 | 192.168.2.44:58598 (observed) |
| 5 | 192.168.2.44:58600 | 192.168.88.60:502 | 192.168.2.44:58600 -> 192.168.88.60:502 (observed) | modbus-tcp | 367 | 5 | 192.168.2.44:58600 (observed) |
| 6 | 192.168.2.44:58602 | 192.168.88.61:502 | 192.168.2.44:58602 -> 192.168.88.61:502 (observed) | modbus-tcp | 433 | 6 | 192.168.2.44:58602 (observed) |

## Ograniczenia

- Zakres tego przebiegu: adresow zaobserwowanych 8, sesji z ladunkiem 7, sesji bez ani jednego segmentu z ladunkiem 2, okno czasowe zrzutu ma dlugosc 0.75273 s.
- Ten raport opisuje wylacznie ruch, ktory dotarl do punktu przechwytywania. Urzadzenie nieobecne w wyniku nie jest urzadzeniem nieobecnym w sieci - jest urzadzeniem, ktorego ruch tego punktu nie minal.
- Urzadzenie stojace za brama protokolu jest widoczne wylacznie pod adresem tej bramy. Adres sieciowy w tym raporcie moze wiec odpowiadac wiecej niz jednemu urzadzeniu fizycznemu.
- Wiele hostow ukrytych za jednym adresem po translacji adresow jest z tego punktu nieodroznialnych. Jeden wiersz inwentarza moze odpowiadac wiecej niz jednemu urzadzeniu.
- Sesji TCP zlozonych wylacznie z pakietow bez ladunku: 2. Nie maja wiersza w macierzy komunikacji, bo nie niosa ani jednego segmentu do rozpoznania - sa policzone tutaj, zeby nie zniknely bez sladu.

Ten raport pochodzi z pionowego przekroju: jeden zrzut, jeden check, jeden punkt normy. Model strefy i kanalu jest placeholderem jednostrefowym wyprowadzonym automatycznie z tego zrzutu, nie zaprojektowana topologia sieci. Numeracja punktu normy jest prowizoryczna i czeka na zestawienie z legalnym egzemplarzem normy.

Pola, ktorych nie da sie ustalic z tego zrzutu, zebrane po nazwie pola:

- sekcja `assets`, pole `gateway`: 8 z 8 wpisow
- sekcja `assets`, pole `role`: 2 z 8 wpisow
- sekcja `assets`, pole `unit_ids`: 3 z 8 wpisow
- sekcja `comm_matrix`, pole `initiator`: 1 z 7 wpisow

## Findingi

### Uzycie protokolu przemyslowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowod: pakiet nr 29, sesja nr 1
- Uzasadnienie: Finding dotyczy samego uzycia protokolu, ktory nie ma mechanizmu uwierzytelnienia nadawcy, niezaleznie od tego, czy w tym zrzucie doszlo do operacji zapisu. Kazdy host widzacy ten segment sieci moze wyslac polecenie, ktore urzadzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wylacznie tego, ze sciezka komunikacji istnieje i jest otwarta. Jest to wlasnosc protokolu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemyslowej alternatywy czesto nie ma.
- Powolanie na norme: IEC-62443-3-3 SR 1.2 - Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Własna, robocza parafraza: punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione, zanim uzyska dostęp do funkcji mających wpływ na bezpieczeństwo procesu - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i tresc parafrazy czekaja na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powolania.)
- Powolanie na norme: CLC/TS 50701 nieustalony-1 - Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Własna, robocza parafraza: dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.

### Uzycie protokolu przemyslowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowod: pakiet nr 34, sesja nr 2
- Uzasadnienie: Finding dotyczy samego uzycia protokolu, ktory nie ma mechanizmu uwierzytelnienia nadawcy, niezaleznie od tego, czy w tym zrzucie doszlo do operacji zapisu. Kazdy host widzacy ten segment sieci moze wyslac polecenie, ktore urzadzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wylacznie tego, ze sciezka komunikacji istnieje i jest otwarta. Jest to wlasnosc protokolu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemyslowej alternatywy czesto nie ma.
- Powolanie na norme: IEC-62443-3-3 SR 1.2 - Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Własna, robocza parafraza: punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione, zanim uzyska dostęp do funkcji mających wpływ na bezpieczeństwo procesu - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i tresc parafrazy czekaja na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powolania.)
- Powolanie na norme: CLC/TS 50701 nieustalony-1 - Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Własna, robocza parafraza: dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.

### Uzycie protokolu przemyslowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowod: pakiet nr 32, sesja nr 3
- Uzasadnienie: Finding dotyczy samego uzycia protokolu, ktory nie ma mechanizmu uwierzytelnienia nadawcy, niezaleznie od tego, czy w tym zrzucie doszlo do operacji zapisu. Kazdy host widzacy ten segment sieci moze wyslac polecenie, ktore urzadzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wylacznie tego, ze sciezka komunikacji istnieje i jest otwarta. Jest to wlasnosc protokolu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemyslowej alternatywy czesto nie ma.
- Powolanie na norme: IEC-62443-3-3 SR 1.2 - Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Własna, robocza parafraza: punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione, zanim uzyska dostęp do funkcji mających wpływ na bezpieczeństwo procesu - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i tresc parafrazy czekaja na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powolania.)
- Powolanie na norme: CLC/TS 50701 nieustalony-1 - Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Własna, robocza parafraza: dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.

### Uzycie protokolu przemyslowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowod: pakiet nr 33, sesja nr 5
- Uzasadnienie: Finding dotyczy samego uzycia protokolu, ktory nie ma mechanizmu uwierzytelnienia nadawcy, niezaleznie od tego, czy w tym zrzucie doszlo do operacji zapisu. Kazdy host widzacy ten segment sieci moze wyslac polecenie, ktore urzadzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wylacznie tego, ze sciezka komunikacji istnieje i jest otwarta. Jest to wlasnosc protokolu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemyslowej alternatywy czesto nie ma.
- Powolanie na norme: IEC-62443-3-3 SR 1.2 - Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Własna, robocza parafraza: punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione, zanim uzyska dostęp do funkcji mających wpływ na bezpieczeństwo procesu - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i tresc parafrazy czekaja na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powolania.)
- Powolanie na norme: CLC/TS 50701 nieustalony-1 - Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Własna, robocza parafraza: dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.

### Uzycie protokolu przemyslowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowod: pakiet nr 35, sesja nr 6
- Uzasadnienie: Finding dotyczy samego uzycia protokolu, ktory nie ma mechanizmu uwierzytelnienia nadawcy, niezaleznie od tego, czy w tym zrzucie doszlo do operacji zapisu. Kazdy host widzacy ten segment sieci moze wyslac polecenie, ktore urzadzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wylacznie tego, ze sciezka komunikacji istnieje i jest otwarta. Jest to wlasnosc protokolu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemyslowej alternatywy czesto nie ma.
- Powolanie na norme: IEC-62443-3-3 SR 1.2 - Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Własna, robocza parafraza: punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione, zanim uzyska dostęp do funkcji mających wpływ na bezpieczeństwo procesu - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i tresc parafrazy czekaja na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powolania.)
- Powolanie na norme: CLC/TS 50701 nieustalony-1 - Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Własna, robocza parafraza: dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa. Nigdy cytat normy.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.

## Zalecenia

- Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.
- Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.
- Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.
- Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.
- Ograniczyc na poziomie sieci grono hostow, ktore moga w ogole otworzyc sesje do sterownika, przez segmentacje i listy kontroli dostepu. Samego protokolu nie da sie uwierzytelnic bez wymiany urzadzen albo bez warstwy posredniczacej.

