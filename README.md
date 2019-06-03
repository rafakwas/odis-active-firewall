# Aktywny firewall

## Instrukcja instalacji
Implementacja aktywnego firewalla pozostawia użytkownika z prostym skryptem
uruchomieniowym.

W ramach projektu dostarczamy gotowego skryptu ​ active_firewall.sh,​ który nie
wymaga dodatkowych czynności użytkownika. Wymagane jest uruchomienie skryptu z
prawami administratora.

Jeśli skrypt nie ma praw wykonywalnych należy mu je przypisać.

```
chmod +x ./afirewall.sh
```

```
sudo ./afirewall.sh
```

Wykonanie powyższych komend spowoduje wgranie konfiguracji, system będzie
chroniony przed niepożądanymi atakami.
