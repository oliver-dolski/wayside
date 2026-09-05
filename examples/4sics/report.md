# Raport Wayside

Wygenerowano: 2026-09-04T00:00:00+00:00

## Streszczenie

Analiza zrzutu `4sics-slice.pcap` wykazała 5 findingów wymagających uwagi.

## Zakres

Zrzut niesie 40 pakietów. W tym zrzucie rozpoznano protokół(y): modbus-tcp, rozpoznawane po kształcie zawartości segmentu, nigdy po numerze portu. Ruch, którego protokołu nie rozpoznano, ma wiersz w macierzy komunikacji z etykietą `tcp` i nie jest podstawą żadnego findingu.
Okno czasowe zrzutu: od 1445499126.04817 do 1445499126.8009 (znaczniki czasu epoki Unix). Snaplen odczytany z nagłówka zrzutu: 65535 bajtów. Ramek uciętych przez snaplen: 0. Zdarzeń rozpoznanych z niską pewnością: 0.

## Metodyka

Każdy finding niesie wskaźnik zaobserwowanego zachowania w ruchu sieciowym, nigdy ocenę, czy instalacja spełnia albo nie spełnia wymagań normy. Waga findingu wynika z poniższych, udokumentowanych kryteriów rubryki (wersja 1.0), nie z wymyślonej skali:

- **low**: Obserwacja o niewielkim wpływie na bezpieczeństwo, bez bezpośredniej ścieżki do zakłócenia działania procesu.
- **medium**: Odstępstwo od dobrej praktyki, które w połączeniu z innym warunkiem może prowadzić do zakłócenia działania procesu.
- **high**: Operacja, która sama w sobie pozwala wpłynąć na stan procesu bez uwierzytelnienia ani autoryzacji nadawcy.
- **critical**: Warunek umożliwiający natychmiastową i bezpośrednią ingerencję w bezpieczeństwo procesu, bez żadnych dodatkowych warunków.

## Inwentarz

### 10.10.10.20

- ip: 10.10.10.20 (observed)
- mac: 00:1c:06:27:64:11 (observed)
- Producent: Siemens Numerical Control Ltd., Nanjing (inferred:oui-lookup)
- Podadresy Unit ID: nieustalone (not-derivable-passively)
- Brama: nieustalone (not-derivable-passively)
- Rola: nieustalona (not-derivable-passively)
- Dowód roli: Zero zdarzeń Modbus powiązanych z tym adresem w tym zrzucie (zadania wysłane: 0, zadania odebrane: 0). (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

### 10.10.10.10

- ip: 10.10.10.10 (observed)
- mac: 28:63:36:89:59:82 (observed)
- Producent: Siemens AG (inferred:oui-lookup)
- Podadresy Unit ID: nieustalone (not-derivable-passively)
- Brama: nieustalone (not-derivable-passively)
- Rola: nieustalona (not-derivable-passively)
- Dowód roli: Zero zdarzeń Modbus powiązanych z tym adresem w tym zrzucie (zadania wysłane: 0, zadania odebrane: 0). (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

### 192.168.88.50

- ip: 192.168.88.50 (observed)
- mac: 00:05:e4:01:24:d3 (observed)
- Producent: Red Lion Controls Inc. (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowód roli: Zadania Modbus wysłane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

### 192.168.2.44

- ip: 192.168.2.44 (observed)
- mac: 00:07:7c:1a:61:83 (observed)
- Producent: Westermo Network Technologies AB (inferred:oui-lookup)
- Podadresy Unit ID: nieustalone (not-derivable-passively)
- Brama: nieustalone (not-derivable-passively)
- Rola: klient Modbus (inferred:modbus-traffic-direction)
- Dowód roli: Zadania Modbus wysłane przez ten adres: 5; zadania Modbus odebrane przez ten adres: 0. (observed)
- Pewność roli: średnia (inferred:event-count-and-direction)

### 192.168.88.100

- ip: 192.168.88.100 (observed)
- mac: 00:e0:62:40:57:66 (observed)
- Producent: HOST ENGINEERING (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowód roli: Zadania Modbus wysłane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

### 192.168.88.20

- ip: 192.168.88.20 (observed)
- mac: 00:a0:45:6f:4b:83 (observed)
- Producent: Phoenix Contact GmbH & Co. KG (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowód roli: Zadania Modbus wysłane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

### 192.168.88.60

- ip: 192.168.88.60 (observed)
- mac: 00:90:e8:26:40:23 (observed)
- Producent: MOXA TECHNOLOGIES CORP., LTD. (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowód roli: Zadania Modbus wysłane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

### 192.168.88.61

- ip: 192.168.88.61 (observed)
- mac: 00:90:e8:27:8c:37 (observed)
- Producent: MOXA TECHNOLOGIES CORP., LTD. (inferred:oui-lookup)
- Podadresy Unit ID: 1 (observed)
- Brama: nieustalone (not-derivable-passively)
- Rola: serwer Modbus (inferred:modbus-traffic-direction)
- Dowód roli: Zadania Modbus wysłane przez ten adres: 0; zadania Modbus odebrane przez ten adres: 1. (observed)
- Pewność roli: niska (inferred:event-count-and-direction)

## Macierz komunikacji

| Sesja | Źródło | Cel | Kierunek | Protokół | Wolumen (B) | Pakietów | Strona inicjująca |
|---|---|---|---|---|---|---|---|
| 0 | 10.10.10.20:49156 | 10.10.10.10:102 | 10.10.10.20:49156 -> 10.10.10.10:102 (inferred:first-observed-sender) | tcp | 634 | 6 | nieustalona (not-derivable-passively) |
| 1 | 192.168.2.44:58597 | 192.168.88.50:502 | 192.168.2.44:58597 -> 192.168.88.50:502 (observed) | modbus-tcp | 260 | 4 | 192.168.2.44:58597 (observed) |
| 2 | 192.168.2.44:58601 | 192.168.88.100:502 | 192.168.2.44:58601 -> 192.168.88.100:502 (observed) | modbus-tcp | 320 | 5 | 192.168.2.44:58601 (observed) |
| 3 | 192.168.2.44:58599 | 192.168.88.20:502 | 192.168.2.44:58599 -> 192.168.88.20:502 (observed) | modbus-tcp | 260 | 4 | 192.168.2.44:58599 (observed) |
| 4 | 192.168.2.44:58598 | 192.168.88.60:44818 | 192.168.2.44:58598 -> 192.168.88.60:44818 (observed) | tcp | 308 | 4 | 192.168.2.44:58598 (observed) |
| 5 | 192.168.2.44:58600 | 192.168.88.60:502 | 192.168.2.44:58600 -> 192.168.88.60:502 (observed) | modbus-tcp | 367 | 5 | 192.168.2.44:58600 (observed) |
| 6 | 192.168.2.44:58602 | 192.168.88.61:502 | 192.168.2.44:58602 -> 192.168.88.61:502 (observed) | modbus-tcp | 433 | 6 | 192.168.2.44:58602 (observed) |

## Ograniczenia

- Zakres tego przebiegu: adresów zaobserwowanych 8, sesji z ładunkiem 7, sesji bez ani jednego segmentu z ładunkiem 2, okno czasowe zrzutu ma długość 0.75273 s.
- Ten raport opisuje wyłącznie ruch, który dotarł do punktu przechwytywania. Urządzenie nieobecne w wyniku nie jest urządzeniem nieobecnym w sieci - jest urządzeniem, którego ruch tego punktu nie minął.
- Urządzenie stojące za bramą protokołu jest widoczne wyłącznie pod adresem tej bramy. Adres sieciowy w tym raporcie może więc odpowiadać więcej niż jednemu urządzeniu fizycznemu.
- Wiele hostów ukrytych za jednym adresem po translacji adresów jest z tego punktu nieodróżnialnych. Jeden wiersz inwentarza może odpowiadać więcej niż jednemu urządzeniu.
- Sesji TCP złożonych wyłącznie z pakietów bez ładunku: 2. Nie mają wiersza w macierzy komunikacji, bo nie niosą ani jednego segmentu do rozpoznania - są policzone tutaj, żeby nie zniknęły bez śladu.

Ten raport pochodzi z pionowego przekroju: jeden zrzut, jeden check, jeden punkt normy. Model strefy i kanału jest placeholderem jednostrefowym wyprowadzonym automatycznie z tego zrzutu, nie zaprojektowaną topologią sieci. Numeracja punktu normy jest prowizoryczna i czeka na zestawienie z legalnym egzemplarzem normy.

Pola, których nie da się ustalić z tego zrzutu, zebrane po nazwie pola:

- sekcja `assets`, pole `gateway`: 8 z 8 wpisów
- sekcja `assets`, pole `role`: 2 z 8 wpisów
- sekcja `assets`, pole `unit_ids`: 3 z 8 wpisów
- sekcja `comm_matrix`, pole `initiator`: 1 z 7 wpisów

## Findingi

### Użycie protokołu przemysłowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowód: pakiet nr 29, sesja nr 1
- Uzasadnienie: Finding dotyczy samego użycia protokołu, który nie ma mechanizmu uwierzytelnienia nadawcy, niezależnie od tego, czy w tym zrzucie doszło do operacji zapisu. Każdy host widzący ten segment sieci może wysłać polecenie, które urządzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wyłącznie tego, że ścieżka komunikacji istnieje i jest otwarta. Jest to własność protokołu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemysłowej alternatywy często nie ma.
- Powołanie na normę: IEC-62443-3-3 SR 1.2
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i treść parafrazy czekają na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powołania.)
- Powołanie na normę: CLC/TS 50701 nieustalony-1
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.

### Użycie protokołu przemysłowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowód: pakiet nr 34, sesja nr 2
- Uzasadnienie: Finding dotyczy samego użycia protokołu, który nie ma mechanizmu uwierzytelnienia nadawcy, niezależnie od tego, czy w tym zrzucie doszło do operacji zapisu. Każdy host widzący ten segment sieci może wysłać polecenie, które urządzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wyłącznie tego, że ścieżka komunikacji istnieje i jest otwarta. Jest to własność protokołu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemysłowej alternatywy często nie ma.
- Powołanie na normę: IEC-62443-3-3 SR 1.2
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i treść parafrazy czekają na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powołania.)
- Powołanie na normę: CLC/TS 50701 nieustalony-1
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.

### Użycie protokołu przemysłowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowód: pakiet nr 32, sesja nr 3
- Uzasadnienie: Finding dotyczy samego użycia protokołu, który nie ma mechanizmu uwierzytelnienia nadawcy, niezależnie od tego, czy w tym zrzucie doszło do operacji zapisu. Każdy host widzący ten segment sieci może wysłać polecenie, które urządzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wyłącznie tego, że ścieżka komunikacji istnieje i jest otwarta. Jest to własność protokołu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemysłowej alternatywy często nie ma.
- Powołanie na normę: IEC-62443-3-3 SR 1.2
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i treść parafrazy czekają na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powołania.)
- Powołanie na normę: CLC/TS 50701 nieustalony-1
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.

### Użycie protokołu przemysłowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowód: pakiet nr 33, sesja nr 5
- Uzasadnienie: Finding dotyczy samego użycia protokołu, który nie ma mechanizmu uwierzytelnienia nadawcy, niezależnie od tego, czy w tym zrzucie doszło do operacji zapisu. Każdy host widzący ten segment sieci może wysłać polecenie, które urządzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wyłącznie tego, że ścieżka komunikacji istnieje i jest otwarta. Jest to własność protokołu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemysłowej alternatywy często nie ma.
- Powołanie na normę: IEC-62443-3-3 SR 1.2
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i treść parafrazy czekają na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powołania.)
- Powołanie na normę: CLC/TS 50701 nieustalony-1
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.

### Użycie protokołu przemysłowego bez mechanizmu uwierzytelnienia w zaobserwowanej komunikacji

- Identyfikator checka: `unauthenticated-industrial-protocol`
- Waga: high (ryzyko: wysokie)
- Dowód: pakiet nr 35, sesja nr 6
- Uzasadnienie: Finding dotyczy samego użycia protokołu, który nie ma mechanizmu uwierzytelnienia nadawcy, niezależnie od tego, czy w tym zrzucie doszło do operacji zapisu. Każdy host widzący ten segment sieci może wysłać polecenie, które urządzenie wykona, a odczyt zaobserwowany w zrzucie dowodzi wyłącznie tego, że ścieżka komunikacji istnieje i jest otwarta. Jest to własność protokołu, nie decyzja ani zaniedbanie operatora instalacji - w starszej instalacji przemysłowej alternatywy często nie ma.
- Powołanie na normę: IEC-62443-3-3 SR 1.2
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Identyfikacja i uwierzytelnienie procesów programowych i urządzeń
  - Parafraza: Punkt dotyczy zapewnienia, że każdy proces programowy i każde urządzenie łączące się z systemem sterowania jest jednoznacznie zidentyfikowane i uwierzytelnione - w odróżnieniu od użytkowników ludzkich, których dotyczy odrębny punkt tego katalogu.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Numeracja punktu i treść parafrazy czekają na zestawienie z legalnym egzemplarzem normy IEC 62443-3-3 w fazie 4. Do tego czasu wpis jest prowizoryczny i nie stanowi potwierdzonego powołania.)
- Powołanie na normę: CLC/TS 50701 nieustalony-1
  - Zakres punktu (opis własny, nie tytuł z egzemplarza): Wymagania bezpieczeństwa dla systemu sterowania i sygnalizacji kolejowej
  - Parafraza: Dokument dotyczy wymagań cyberbezpieczeństwa stawianych systemom sterowania ruchem kolejowym i sygnalizacji, w tym ochrony ich prawidłowego działania przed celowym i przypadkowym naruszeniem bezpieczeństwa.
  - Status: **PROWIZORYCZNE, NIEZWERYFIKOWANE** (Dokument ma status specyfikacji technicznej CENELEC, nie normy europejskiej, stosuje się go więc dobrowolnie - raport nie przedstawia go jako podstawy obowiązkowej (decyzja 0004). Numeracja punktu nie została zestawiona z egzemplarzem, bo egzemplarza projekt nie kupuje; wpis jest z tego powodu prowizoryczny (decyzja 0006).)
- Zalecenie: Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.

## Zalecenia

- Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.
- Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.
- Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.
- Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.
- Ograniczyć na poziomie sieci grono hostów, które mogą w ogóle otworzyć sesję do sterownika, przez segmentację i listy kontroli dostępu. Samego protokołu nie da się uwierzytelnić bez wymiany urządzeń albo bez warstwy pośredniczącej.

