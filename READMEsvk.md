# Sniffer paketov
Sieťový analyzátor, ktorý zachytáva pakety z rozhrania ktoré bolo špecifikované užívateľom pomocou parametra -i, avšak ak parameter -i nebol zadaný tak analyzátor zobrazí aktívne rozhrania, konkrétne ich názov, ip adresu a broadcast.

## Rozšírenia
Program spracováva taktiež ICMP pakety a teda program aj akceptuje nové dva argumenty -c a --icmp, ktoré budú filtrovať iba ICMP pakety

## Akceptované argumenty
- -i \<rozhranie>  = špecifikuje rozhranie z ktorého bude zachytávať pakety
- -n \<počet paketov> = špecifikuje počet zobrazených paketov 
- -p \<číslo portu> = iba pakety s týmto portom budu zobrazené 
- -t/--tcp = iba tcp pakety budú zobrazené
- -u/--udp = iba udp pakety budú zobrazené
- -c/--icmp = iba icmp pakety budú zobrazené
- -h = zobrazí nápovedu

## Príklady spustenia
-- vytlačí 200 paketov  <br>
sudo ./sniffer -i enx00e04c68021d -n 200
-- vytlačí 200 paketov  <br>
sudo ./sniffer -i enx00e04c68021d -t
-- vytlačí 200 paketov  <br>
sudo ./sniffer -i enx00e04c68021d -u

## Zoznam odovzdaných súborov
- sniffer.cpp = zdrojový kód sieťového analyzátora
- Makefile 
- READNE.md = README v slovenčine
- READMEeng.md = README v angličtine
- manual.pdf
