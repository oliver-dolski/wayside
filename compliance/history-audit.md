---
requirement: PUB-05
scope: repository-history-identity-patterns
audited_on: 2026-09-09
head_sha: 0cb6292e77385aaa805aa07919fc3b3d8c944852
surfaces: tree-content, commit-message, file-name
rules_checked: identity-private-ipv4, identity-mac-address, identity-device-name, identity-project-name
exceptions_file: .confidentiality-allow
result: clean
author: Oliver Dolski
confirmed_on: 2026-09-09
---

Ten rekord zapisuje WYNIK PRZEBIEGU skanu trzech powierzchni calej historii
repozytorium, powiazany ze skrotem HEAD z chwili tego przebiegu - nie
zapisuje zadnego dopasowanego fragmentu tresci historii ani zadnej nazwy
pliku z trafieniem. Pola `author` i `confirmed_on` sa jedynym sladem tego,
ze wynik zostal przez kogos przeczytany; wykonawca planu ich nie wypelnia.

## Zakres

Trzy powierzchnie, kazda osobnym skanem z osobnym parsowaniem wyjscia
(`tests/test_history_audit.py`):

- **tree-content** - tresc drzew wszystkich rewizji osiagalnych ze
  wszystkich referencji (`git rev-list --all` plus jedno wywolanie
  `git grep` nad wszystkimi rewizjami naraz).
- **commit-message** - komunikaty wszystkich commitow (`git log --all`,
  format z rekordem ograniczonym bajtem zerowym).
- **file-name** - nazwy plikow z drzewa kazdej rewizji (`git ls-tree -r
  --name-only -z` na kazda rewizje, suma nazw ze wszystkich rewizji).

Kazda powierzchnia jest sprawdzona TYMI SAMYMI czterema regulami ksztaltu
warstwy tozsamosciowej, co bramka biezaca (`scripts/confidentiality_guard.py`,
D-19): `identity-private-ipv4`, `identity-mac-address`, `identity-device-name`,
`identity-project-name`. Piata regula (`identity-local-literal`) dziala
WYLACZNIE lokalnie z pliku gitignorowanego i nie jest czescia tego audytu -
ta sama granica, ktora README nazywa dla bramki biezacej w CI.

## Wynik

`clean` - zero trafien na wszystkich trzech powierzchniach poza wartosciami
zadeklarowanymi i sciezkami wyjetymi w pliku wyjatkow. Wynik jest FAKTEM
MASZYNOWYM z rzeczywistego przebiegu na skrocie HEAD zapisanym powyzej
(`uv run pytest -o addopts="-q" -m slow tests/test_history_audit.py`, 11
testow zielonych).

## Wyjatki

Plik wyjatkow: `.confidentiality-allow`. Ten sam plik, co bramka biezaca -
D-19 wymaga JEDNEJ listy wyjatkow, nie drugiej obok. Na dzien tego audytu
plik niesie: dwa wyjatki sciezki dla reguly nazwy wlasnej
(`identity-path:identity-project-name:...`), oraz 32 deklaracje wartosci
adresowych (`identity-value:...`) pogrupowane po pochodzeniu, z komentarzem
nazywajacym zrodlo nad kazda grupa. Pelna tresc kazdego wpisu stoi w tamtym
pliku, nie tutaj - ten rekord nie powtarza jej liczby ani ksztaltu poza tym,
co jest potrzebne do zrozumienia zakresu audytu.

## Kontrakt naprawy

Trafienie w historii repozytorium (tresc drzewa, komunikat commita albo
nazwa pliku) NIE jest sytuacja do naprawienia kolejnym commitem - tresc juz
jest w historii. Wymagane jest przepisanie historii przez `git filter-repo`
PRZED jakimkolwiek publicznym pushem. Jesli publiczny push juz sie odbyl,
przepisanie historii nie cofa faktu, ze tresc mogla zostac zescrapowana albo
zmirrorowana. To samo brzmienie stoi w komunikacie testu
(`tests/test_history_audit.py::REMEDIATION_MESSAGE`) i w README.

## Warunki rewizji

Ten rekord wymaga ponowienia (nowego przebiegu skanu i nowego zapisu pola
`head_sha` razem z data), gdy zajdzie ktorekolwiek z ponizszych: zmiana
zbioru wzorcow warstwy tozsamosciowej, zmiana pliku wyjatkow
`.confidentiality-allow`, albo gdy biezacy HEAD odjedzie od skrotu
zapisanego powyzej na tyle, ze audyt ma zostac powtorzony przed publicznym
pushem - to sprawdza maszynowo `scripts/check_history_audit_gate.py` z flaga
`--require-current`.
