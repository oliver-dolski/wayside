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

## Uruchomienie

```powershell
uv run wayside inspect <plik.pcap>
```

## Testy

```powershell
uv run pytest
```
