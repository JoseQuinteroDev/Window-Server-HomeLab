# 🏗️ Montaje del Laboratorio — Red Empresarial AD (Hyper-V)

**Objetivo:** un dominio Windows realista y **aislado** para practicar como Blue Team: Active Directory, DNS, GPO, auditoría, y ataques de identidad (Kerberoasting, AS-REP Roasting) con su detección.

> Marca cada `[ ]` al completarlo. Cada **FASE** = un hito (y un buen punto de commit en el repo).

---

## 🎯 Topología objetivo

```
         vSwitch  "LAB-Net"  (Internal — red 10.10.10.0/24, AISLADA)
   ┌───────────────────┬───────────────────────┬──────────────────────┐
   │      DC01         │        WIN11          │        KALI          │
   │ Windows Server2025│   Windows 11 Pro      │   Kali Linux         │
   │ 10.10.10.10       │   10.10.10.21         │   10.10.10.66        │
   │ AD DS + DNS + GPO  │ Endpoint de dominio   │ Atacante             │
   │ Dominio corp.local │ + Sysmon              │ + impacket           │
   └───────────────────┴───────────────────────┴──────────────────────┘
   DNS de TODAS las máquinas del dominio  →  10.10.10.10 (DC01)
```

**Plan de nombres / IPs**

| Máquina | Rol | Hostname | IP | DNS | RAM |
|---|---|---|---|---|---|
| DC01 | Controlador de dominio (AD DS, DNS) | `DC01` | 10.10.10.10/24 | 127.0.0.1 | 4 GB |
| WIN11 | Endpoint unido al dominio | `WIN11` | 10.10.10.21/24 | 10.10.10.10 | 4 GB |
| KALI | Atacante | `kali` | 10.10.10.66/24 | 10.10.10.10 | 2–3 GB |

- **Dominio:** `corp.local` · **NetBIOS:** `CORP`
- **Regla de oro de aislamiento:** el tráfico de dominio/ataque vive SIEMPRE en `LAB-Net` (Internal, sin internet). Internet solo se da de forma **temporal** (segundo adaptador "Default Switch") cuando una VM necesita actualizarse o descargar herramientas, y se quita después.

---

## FASE 0 — Preparar el host (tu Windows 11)

> Estos pasos van en una **PowerShell como Administrador** (clic derecho → "Ejecutar como administrador"). Requieren reinicio.

**0.1 Habilitar Hyper-V**
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```
- [ ] Ejecutado · `[ ]` **Reiniciar** el equipo cuando lo pida.
- Compatible con tu WSL2/Docker (ambos usan el mismo hipervisor).

**0.2 Crear el switch virtual aislado** (tras reiniciar, PowerShell admin)
```powershell
New-VMSwitch -Name "LAB-Net" -SwitchType Internal
# IP del host en esa red (para poder gestionar/copiar archivos a las VMs)
$if = (Get-NetAdapter | Where-Object { $_.Name -like "*LAB-Net*" }).ifIndex
New-NetIPAddress -IPAddress 10.10.10.1 -PrefixLength 24 -InterfaceIndex $if
```
- [ ] Switch `LAB-Net` creado · host con IP 10.10.10.1

**0.3 Carpeta para las VMs**
```powershell
New-Item -ItemType Directory -Force "C:\Lab\VMs"
New-Item -ItemType Directory -Force "C:\Lab\ISOs"
```
- [ ] Carpetas creadas (mueve aquí el ISO de Server 2016)

**0.4 Descargas — ESTADO (2026-06-13)**
- [x] **Windows Server 2025 Eval** (Desktop Experience, 180 días) → `C:\Lab\ISOs\WinServer2025_Eval_x64.iso` (7.59 GB). *Decisión: usamos 2025 en vez del 2016 que tenías — LTSC vigente + defaults de seguridad modernos.*
- [x] **Windows 11 25H2** (instalar **Pro**) → `C:\Lab\ISOs\Win11_25H2_x64.iso` (7.89 GB).
- [ ] **Kali Linux** — imagen **pre-construida Hyper-V** (`kali.org/get-kali/#kali-virtual-machines`). **DIFERIDO**: no cabe en C: ahora → SSD externo o tras liberar disco.

> ⚠️ **Espacio (real 2026-06-13):** ~35 GB libres en C:. Los 2 VHDX (DC01 ~17 GB + WIN11 ~23 GB) caben SOLO con discos **dinámicos** y **borrando cada ISO tras instalar su VM** (DC01 → borra ISO server → WIN11 → borra ISO win11). Acabas con ~15 GB libres. **Kali requiere SSD externo USB** (mueve `C:\Lab` ahí) — es lo cómodo.

---

## FASE 1 — DC01: Windows Server + Active Directory + DNS

**1.1 Crear la VM (PowerShell admin)**
```powershell
$vm = "DC01"
New-VM -Name $vm -MemoryStartupBytes 4GB -Generation 2 -Path "C:\Lab\VMs" `
  -NewVHDPath "C:\Lab\VMs\$vm\$vm.vhdx" -NewVHDSizeBytes 40GB -SwitchName "LAB-Net"
Set-VM -Name $vm -DynamicMemory -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB -ProcessorCount 2
# Montar el ISO de instalación
Add-VMDvdDrive -VMName $vm -Path "C:\Lab\ISOs\WinServer2025_Eval_x64.iso"
# Orden de arranque: DVD primero
$dvd = Get-VMDvdDrive -VMName $vm
Set-VMFirmware -VMName $vm -FirstBootDevice $dvd
# Gen2 necesita Secure Boot con plantilla Microsoft (ya por defecto). Para ISOs problemáticos:
# Set-VMFirmware -VMName $vm -EnableSecureBoot Off
Start-VM -Name $vm
```
- [x] VM creada y arrancada (conéctate con "Conexión a la máquina virtual") · **(2026-06-13)**

> ⚠️ **Gotcha de arranque (Gen2) — "Press any key to boot from CD or DVD..."**
> Al arrancar desde el DVD, Hyper-V muestra ese aviso **solo unos ~5 s**. Si NO pulsas una tecla en la ventana de *VMConnect*, `cdboot.efi` aborta y la VM cae al **resumen de arranque UEFI** con:
> ```
> 1. SCSI DVD   -> The boot loader failed.
> 2. Network    -> A boot image was not found.
> 3. SCSI Disk  -> The boot loader did not load an operating system.
> No operating system was loaded.
> ```
> Esto **NO es mala configuración** (orden de arranque DVD→Red→Disco, Secure Boot `MicrosoftWindows` e ISO son correctos): solo faltó la pulsación. **Solución:** ten la ventana de VMConnect abierta y **pulsa una tecla en cuanto aparezca el aviso**; si ya cayó al resumen, pulsa "Restart now" y esta vez sí pulsa a tiempo. *(Síntoma típico: VM "Running" pero CPU 0 %, sin heartbeat y VHDX a 0 GB = el SO nunca llegó a instalarse.)*

**1.2 Instalar Windows Server 2025** *(Evaluation, 180 días — sin clave)*
- Al elegir edición: **"Windows Server 2025 Standard Evaluation (Desktop Experience)"** ← con GUI (NO la opción sin "Desktop Experience", que es Server Core sin escritorio).
- Instalación personalizada (**Custom**) → selecciona el disco de 40 GB (Drive 0, sin asignar) → Next (Setup crea las particiones GPT/UEFI solo).
- Define la contraseña del **Administrador** local. **Credencial de lab documentada:** `Administrator` / `Lab.Admin.2026!` *(para que la promoción por PowerShell Direct funcione; cámbiala si prefieres, pero dímela).*
- [x] SO instalado y dentro del escritorio · **Login de dominio: `CORP\Administrator` / `Lab.Admin.2026!`** (2026-06-13)

**1.3 Configuración base (en una PowerShell admin DENTRO de DC01)**
```powershell
Rename-Computer -NewName "DC01" -Restart
```
Tras reiniciar, IP estática:
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
```
- [x] Renombrado a DC01 · IP 10.10.10.10 fija · *(hecho por PowerShell Direct, 2026-06-13)*

**1.4 Promover a Controlador de Dominio (crea el bosque + DNS)**
```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
Import-Module ADDSDeployment
Install-ADDSForest -DomainName "corp.local" -DomainNetbiosName "CORP" `
  -InstallDns -Force `
  -SafeModeAdministratorPassword (ConvertTo-SecureString "Lab.SafeMode.2026!" -AsPlainText -Force)
# Reinicia solo. Al volver, ya eres CORP\Administrator.
```
- [x] Bosque `corp.local` creado · DNS instalado automáticamente · DomainMode/ForestMode **Windows2025** (2026-06-13)
- **Validación:** ✅ `Get-ADDomain` → corp.local (NetBIOS CORP, PDC DC01.corp.local) · ✅ `Resolve-DnsName dc01.corp.local` → 10.10.10.10 · servicios NTDS/DNS/kdc/Netlogon Running

---

## FASE 2 — Estructura "empresa" en AD (OUs, usuarios, grupos)

> En DC01, PowerShell admin. Crea una empresa pequeña realista.

**2.1 Unidades organizativas (OUs)**
```powershell
$base = "DC=corp,DC=local"
"Employees","Servers","Workstations","ServiceAccounts","Groups","AdminAccounts" | ForEach-Object {
  New-ADOrganizationalUnit -Name $_ -Path $base -ProtectedFromAccidentalDeletion $false
}
```

**2.2 Usuarios de ejemplo**
```powershell
$pw = ConvertTo-SecureString "P@ssw0rd.2026" -AsPlainText -Force
$users = @(
  @{N="Juan Perez";  S="j.perez";  OU="Employees"},
  @{N="Maria Lopez"; S="m.lopez";  OU="Employees"},
  @{N="Ana Garcia";  S="a.garcia"; OU="Employees"},
  @{N="Helpdesk Op"; S="helpdesk"; OU="Employees"}
)
foreach ($u in $users) {
  New-ADUser -Name $u.N -SamAccountName $u.S -UserPrincipalName "$($u.S)@corp.local" `
    -Path "OU=$($u.OU),DC=corp,DC=local" -AccountPassword $pw -Enabled $true `
    -ChangePasswordAtLogon $false
}
```

**2.3 Grupos y membresías**
```powershell
New-ADGroup -Name "IT-Admins" -GroupScope Global -Path "OU=Groups,DC=corp,DC=local"
New-ADGroup -Name "Finance"   -GroupScope Global -Path "OU=Groups,DC=corp,DC=local"
Add-ADGroupMember -Identity "IT-Admins" -Members j.perez
Add-ADGroupMember -Identity "Finance"   -Members m.lopez,a.garcia
```
- [x] OUs, usuarios y grupos creados (Employees/Servers/Workstations/ServiceAccounts/Groups/AdminAccounts; j.perez/m.lopez/a.garcia/helpdesk; IT-Admins, Finance) (2026-06-13)

**2.4 Objetivos deliberados para practicar ataques de identidad** ⚔️
```powershell
# (A) Cuenta de servicio CON SPN -> objetivo de KERBEROASTING
New-ADUser -Name "svc_sql" -SamAccountName "svc_sql" `
  -UserPrincipalName "svc_sql@corp.local" -Path "OU=ServiceAccounts,DC=corp,DC=local" `
  -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
setspn -S MSSQLSvc/sql01.corp.local:1433 corp\svc_sql

# (B) Usuario SIN preautenticación Kerberos -> objetivo de AS-REP ROASTING
Set-ADAccountControl -Identity a.garcia -DoesNotRequirePreAuth $true
```
> La contraseña de `svc_sql` es débil a propósito (`Summer2024!`) para que el crackeo offline funcione en la práctica. En el mundo real esto es exactamente la mala práctica que cazamos.
- [x] `svc_sql` con SPN `MSSQLSvc/sql01.corp.local:1433` (+RC4 0x17 señuelo) · `a.garcia` sin preauth (DoesNotRequirePreAuth=True) (2026-06-13)

> ⚠️ **Nota Server 2025 (Kerberos AES vs RC4):** 2025 entrega tickets **AES (0x12)** por defecto y RC4 va desactivándose. Para reproducir el **Kerberoasting clásico RC4 (`0x17`)**, habilita RC4 SOLO en esta cuenta señuelo:
> ```powershell
> Set-ADUser svc_sql -Replace @{ "msDS-SupportedEncryptionTypes" = 0x17 }   # DES+RC4+AES -> RC4 ofertable
> ```
> Alternativa (más realista): déjalo en AES y **detecta igual por el patrón de peticiones 4769** a la cuenta de servicio — el evento aparece con o sin RC4; solo cambia el `Ticket Encryption Type`.

---

## FASE 3 — WIN11: endpoint unido al dominio

**3.1 Crear la VM** (host, PowerShell admin) — igual que DC01 pero con el ISO de Win11:
```powershell
$vm="WIN11"
New-VM -Name $vm -MemoryStartupBytes 4GB -Generation 2 -Path "C:\Lab\VMs" `
  -NewVHDPath "C:\Lab\VMs\$vm\$vm.vhdx" -NewVHDSizeBytes 64GB -SwitchName "LAB-Net"   # 64 GB: Win11 exige >=64 GB de disco; dinamico => solo usa lo real
Set-VM -Name $vm -DynamicMemory -MemoryMinimumBytes 1GB -MemoryMaximumBytes 4GB -ProcessorCount 2
Add-VMDvdDrive -VMName $vm -Path "C:\Lab\ISOs\Win11_25H2_x64.iso"
# Win11 exige TPM: habilitar vTPM
Set-VMKeyProtector -VMName $vm -NewLocalKeyProtector
Enable-VMTPM -VMName $vm
Set-VMFirmware -VMName $vm -FirstBootDevice (Get-VMDvdDrive -VMName $vm)
Start-VM -Name $vm
```
> **Arranque del instalador (gotcha Gen2):** Win11 también pide pulsar tecla en *"Press any key to boot from CD"*. Con arranque en frío + vTPM la ventana se desplaza; usa `lab-tools\Boot-VMPressAnyKey.ps1 -VMName WIN11` (cadencia densa 400 ms) y verifica con `Capture-VMConsole.ps1`.
>
> **Cuenta local en OOBE (Win11 25H2, sin internet):** en *"Let's connect you to a network"* pulsa `Shift+F10` → escribe `start ms-cxh:localonly` → Enter (en builds antiguas era `OOBE\BYPASSNRO`). Crea la cuenta local **`labadmin` / `Lab.Admin.2026!`** (documentada para promover/unir por PowerShell Direct). Edición: **Windows 11 Pro** (Home no une a dominio).

> ✅ **Camino AUTOMÁTICO usado (2026-06-13) — instalación desatendida, cero clics:**
> En vez del wizard manual se usó un `autounattend.xml` (en `lab-tools/configs/win11-autounattend.xml`) que elige **Pro**, particiona en UEFI, salta el OOBE/red y crea la cuenta local `labadmin`. Flujo:
> 1. `lab-tools\Recreate-WIN11.ps1` — VM limpia (Gen2 + vTPM).
> 2. `lab-tools\New-AutounattendIso.ps1 -SourceDir C:\Lab\unattend -OutIso C:\Lab\autounattend.iso` — empaqueta el answer file en ISO (IMAPI2, sin ADK) y se adjunta como 2º DVD.
> 3. `lab-tools\Boot-VMUntilSetup.ps1 -VMName WIN11` — arranca al instalador de forma fiable (reintentos + detección por `MemoryDemand`).
> 4. `lab-tools\Wait-VMReady.ps1` — espera al escritorio. Resultado: **Win11 Pro instalado sin intervención.**

**3.2 Red + unión al dominio** (PowerShell admin dentro de WIN11)
```powershell
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.10.10.21 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 10.10.10.10
Rename-Computer -NewName "WIN11" -Restart
# Tras reiniciar:
Add-Computer -DomainName "corp.local" -Credential (Get-Credential CORP\Administrator) -Restart
```
- [x] WIN11 con IP .21, DNS al DC, **unido a corp.local** (por PowerShell Direct, 2026-06-13)
- **Validación:** ✅ `PartOfDomain=True` · `Domain=corp.local` · `Test-ComputerSecureChannel=True` (confianza con el DC sana). Pendiente: probar inicio de sesión interactivo como `CORP\j.perez`.

---

## FASE 4 — GPO y AUDITORÍA (el corazón Blue Team) 🛡️

> Sin auditoría no hay telemetría que cazar. **Esta fase es la más importante para un analista SOC.** En DC01 → "Administración de directivas de grupo" (gpmc.msc) o por PowerShell.

**4.1 Política de auditoría avanzada** (crea una GPO `Audit-Baseline` enlazada al dominio):
Activa (Configuración de equipo → Directivas → Config. de Windows → Config. de seguridad → Config. de directiva de auditoría avanzada):
- **Seguimiento detallado → Auditar creación de procesos** = Correcto → genera **4688**
- **Inicio/cierre de sesión → Auditar inicio de sesión** = Correcto y erróneo → **4624/4625**
- **Acceso a DS → Auditar operaciones de tickets de servicio Kerberos** = Correcto → **4769** (¡clave para detectar Kerberoasting!)
- **Acceso a DS → Auditar servicio de autenticación Kerberos** = Correcto → **4768/4771** (AS-REP)
- **Administración de cuentas → Auditar admin. de cuentas de usuario** = Correcto → **4720/4724/4738**

**4.2 Línea de comandos en 4688** (GPO):
Config. equipo → Plantillas administrativas → Sistema → Auditar creación de procesos → **"Incluir línea de comandos"** = Habilitado.

**4.3 Logging de PowerShell** (GPO) — Plantillas administrativas → Componentes de Windows → Windows PowerShell:
- **Registro de bloques de script** = Habilitado → **4104**
- **Registro de módulos** = Habilitado · **Transcripción** = Habilitado (a `C:\PSLogs`)

**4.4 Endurecimiento básico** (GPO):
- Política de contraseñas (longitud ≥ 12, complejidad).
- Banner de inicio de sesión legal.
- (Más adelante) restringir NTLM, firmado SMB, LSA Protection.

**4.5 Desplegar Sysmon por GPO** (lo afinamos en la fase de telemetría):
- GPO con tarea programada/script de inicio que instala Sysmon con la config curada (partimos de la de tu repo `Threat Hunting on my own PC/detections/sysmon/`).

Forzar y verificar:
```powershell
# en los clientes:  gpupdate /force   ·   gpresult /r
# en DC01: comprobar GPOs
Get-GPO -All | Select DisplayName
```
- [x] Auditoría (4688+cmdline, 4624/25, 4769, 4768, 4720) activa · PowerShell SBL/Module/Transcription. **GPO `Audit-Baseline` enlazada al dominio (2026-06-13).** Sysmon → fase de telemetría.
- **Validación:** ✅ `auditpol` en WIN11 confirma las 5 subcategorías; **4688 capturado CON línea de comandos** (`cmd /c echo SOC-LAB-MARKER-4688`, padre `powershell.exe`) y **4104** registrado. Montado de forma scriptada con [`lab-tools/Configure-AuditGPO.ps1`](lab-tools/Configure-AuditGPO.ps1) (audit.csv en SYSVOL + CSE).

---

## FASE 5 — KALI: la caja atacante

**5.1 Importar la VM de Kali** (host, PowerShell admin):
```powershell
# Descomprime la imagen Hyper-V de Kali y luego:
Import-VM -Path "C:\Lab\ISOs\kali\<...>\Virtual Machines\<GUID>.vmcx" -Copy -GenerateNewId `
  -VirtualMachinePath "C:\Lab\VMs\KALI" -VhdDestinationPath "C:\Lab\VMs\KALI"
Connect-VMNetworkAdapter -VMName "kali-linux-*" -SwitchName "LAB-Net"
Start-VM -Name "kali-linux-*"
```
**5.2 Configurar Kali** (dentro de Kali; user/pass por defecto `kali/kali`):
```bash
sudo ip addr add 10.10.10.66/24 dev eth0      # o configurar estático en /etc/network/interfaces
echo "nameserver 10.10.10.10" | sudo tee /etc/resolv.conf
sudo apt update && sudo apt install -y impacket-scripts   # GetUserSPNs.py, GetNPUsers.py
ping dc01.corp.local
```
- [ ] Kali en la red, resuelve dc01.corp.local, impacket instalado

---

## FASE 6 — Validación end-to-end: tu primer Kerberoast ⚔️→🛡️

> Esto confirma que el lab **entero** funciona y que la telemetría llega. (El proyecto de Detection Engineering profundizará en esto.)

**Ataque (desde Kali):**
```bash
# Kerberoasting: pedir el ticket del SPN de svc_sql
GetUserSPNs.py corp.local/j.perez:'P@ssw0rd.2026' -dc-ip 10.10.10.10 -request
# AS-REP Roasting: usuario sin preauth (a.garcia)
GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile usuarios.txt -no-pass
```
**Detección (en DC01, Visor de eventos / luego KQL en Sentinel):**
- Busca **4769** (solicitud de ticket de servicio) con `Ticket Encryption Type = 0x17` (RC4) → patrón clásico de Kerberoasting.
- [ ] Ataque ejecutado · evento 4769 visible → **el lab funciona de punta a punta** ✅

---

## ✅ Checklist de hitos (= commits)
- [x] FASE 0 — Host: Hyper-V + LAB-Net + carpetas + ISOs **(2026-06-13)**
- [x] FASE 1 — DC01: Server + AD DS + DNS (corp.local) **(2026-06-13)**
- [x] FASE 2 — Estructura AD (OUs, usuarios, grupos, objetivos Kerberos) **(2026-06-13)**
- [x] FASE 3 — WIN11 unido al dominio **(2026-06-13, instalación desatendida)**
- [x] FASE 4 — GPO + Auditoría (¡telemetría!) **(2026-06-13, validada end-to-end con 4688+cmdline y 4104)**
- [ ] FASE 5 — Kali atacante
- [ ] FASE 6 — Kerberoast end-to-end validado

## 🔒 Reglas del lab
- Aislado en `LAB-Net`. Internet solo temporal y a propósito (nunca en DC01).
- *Snapshots* (checkpoints) ANTES de cada sesión de ataque: `Checkpoint-VM -Name DC01 -SnapshotName "limpio"`.
- Software con **licencias de evaluación** — nada de cracks (la lección del incidente real).

## 📌 Próximo paso inmediato (actualizado 2026-06-13)
1. ✅ Hyper-V habilitado · ✅ ISOs Win11 + Server 2025 en `C:\Lab\ISOs`.
2. En **PowerShell como Administrador**, ejecutar `C:\Lab\build-lab.ps1` → crea el switch `LAB-Net` + las VMs **DC01** y **WIN11** de un tirón (o haz a mano 0.2 + FASE 1.1 + FASE 3.1).
3. Arrancar DC01, instalar Server 2025 (Desktop Experience) → **FASE 1.4** (promover a DC `corp.local`).
4. **KALI** cuando tengas SSD externo / más disco.
