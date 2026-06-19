# 🚀 Despliegue y validación — detecciones derivadas de Akira

> **Honestidad metodológica (norma del portfolio):** las 7 reglas están **autoradas y listas**, pero
> **aún no desplegadas/validadas en vivo**. Desplegarlas modifica la infraestructura del SIEM (manager
> Wazuh) y requiere el lab encendido + autorización explícita — el mismo criterio que aplicamos en el
> [Purple Team (P5)](../../05-purple-team/attack-detection-matrix.md) con la regla 100180 antes de validarla.
> Este documento deja el despliegue **turnkey**: runbook + resultados esperados.

## Estado actual

| Regla | Técnica | Autorada | Desplegada | Validada en vivo |
|---|---|:--:|:--:|:--:|
| 100181 | T1490 (shadow WMI) | ✅ | ⏳ | ⏳ |
| 100190 | T1003.001 (LSASS comsvcs) | ✅ | ⏳ | ⏳ |
| 100191 | T1003.001 (LSASS procdump) | ✅ | ⏳ | ⏳ |
| 100200 | T1018 / T1482 (recon AD) | ✅ | ⏳ | ⏳ |
| 100210 | T1087.002 (BloodHound 4104) | ✅ | ⏳ | ⏳ |
| 100211 | T1087.002 (SharpHound cmdline) | ✅ | ⏳ | ⏳ |
| 100220 | T1136.001 (crear cuenta) | ✅ | ⏳ | ⏳ |
| 100230 | T1021.001 / T1562.004 (RDP) | ✅ | ⏳ | ⏳ |

## Runbook de despliegue (manager Wazuh `10.10.10.20`)

```bash
# 1) Copiar el bloque de reglas al manager y anexarlo al ruleset local
#    (desde el host, vía la copia compartida del repo, o pegando el XML)
sudo sh -c 'cat akira-local-rules.xml >> /var/ossec/etc/rules/local_rules.xml'
#    (o integrarlo en el local_rules.xml canónico de wazuh/rules/ y sincronizar)

# 2) Validar la sintaxis del ruleset y reiniciar el manager
sudo /var/ossec/bin/wazuh-logtest -t           # comprueba que cargan sin error
sudo systemctl restart wazuh-manager

# 3) Confirmar que las reglas están cargadas
sudo grep -E 'id="(100181|10019[01]|100200|10021[01]|100220|100230)"' /var/ossec/etc/rules/local_rules.xml
```

```powershell
# 4) Desde el HOST (PowerShell admin, WIN11 encendida): lanzar la simulación benigna
.\tests\Invoke-AkiraSimulation.ps1
```

```bash
# 5) En el manager: verificar las alertas generadas (buscar el tag de simulación)
sudo grep -E 'SOC-AKIRA-SIM|10018[01]|10019[01]|100200|10021[01]|100220|100230' /var/ossec/logs/alerts/alerts.log
```

## Resultados esperados (criterio de "validado")

| Trigger de la simulación | Telemetría | Regla esperada | Nivel | MITRE |
|---|---|---|---|---|
| `nltest /dclist:corp.local` · `net group "Domain Admins" /domain` | 4688 | **100200** | 10 | T1018, T1482 |
| marcador `comsvcs.dll MiniDump …` | 4688 | **100190** | 13 | T1003.001 |
| `Write-Output 'Invoke-BloodHound -CollectionMethod All'` | 4104 (+4688) | **100210** (y 100211) | 12 | T1087.002 |
| marcador `net user … /add` | 4688 | **100220** | 10 | T1136.001 |
| marcador `netsh advfirewall … rdp 3389` | 4688 | **100230** | 10 | T1021.001, T1562.004 |
| marcador `Get-WmiObject Win32_Shadowcopy … Delete` | 4688 | **100181** | 13 | T1490 |

> Al disparar reglas de nivel ≥10, el **Active Response** del [Proyecto 1](../../01-soc-automation-playbook/automation/wazuh-active-response.md)
> (`open-soc-case`) debería abrir un caso por cada una en `/var/ossec/logs/soc-cases.log` — igual que en P1/P4/P5.

## Nota sobre `100191` (procdump) y la vía en memoria de BloodHound

- `100191` (procdump -ma lsass) y `100211` (SharpHound.exe) cubren variantes que el lab **no tiene herramienta** para emular de forma nativa (no hay procdump ni el binario SharpHound) → quedan **ARMADAS** (como la AS-REP del P3 sin KALI), no validadas en vivo. Su lógica es espejo de 100190/100210, ya cubiertos por la simulación.
- Cuando exista la VM **KALI** (diferida por disco), se podrán emular con herramientas reales (Rubeus, SharpHound, Impacket) y cerrar también esos casos.
