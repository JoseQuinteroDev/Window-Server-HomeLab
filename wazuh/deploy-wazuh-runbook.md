# 📕 Runbook — desplegar Wazuh en el lab (manager + agentes)

> Objetivo: levantar el **manager Wazuh** en `LAB-Net` y conectar **agentes en DC01 y WIN11**, cargar
> `rules/local_rules.xml` y disparar una alerta real. Todo queda **aislado** salvo una ventana de internet
> solo para instalar. Requisitos: ~51 GB libres en C: ✅, ~4 GB RAM para la VM.

---

## 0. Checkpoint primero
Antes de tocar nada, snapshot de las VMs que se modifican (se les instala agente):
```powershell
Checkpoint-VM -Name DC01  -SnapshotName "pre-wazuh-agent_$(Get-Date -Format yyyyMMdd)"
Checkpoint-VM -Name WIN11 -SnapshotName "pre-wazuh-agent_$(Get-Date -Format yyyyMMdd)"
```

## 1. Crear la VM `WAZUH` (en el host, consola elevada)
```powershell
$vhd = "C:\Lab\VMs\WAZUH\WAZUH.vhdx"
New-VM -Name WAZUH -Generation 2 -MemoryStartupBytes 4GB -NewVHDPath $vhd -NewVHDSizeBytes 32GB -SwitchName "LAB-Net"
Set-VM -Name WAZUH -ProcessorCount 2 -DynamicMemory -MemoryMinimumBytes 2GB -MemoryMaximumBytes 4GB
# Ubuntu Server es Linux -> desactivar Secure Boot con plantilla de Microsoft UEFI:
Set-VMFirmware -VMName WAZUH -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority
Add-VMDvdDrive -VMName WAZUH -Path "C:\Lab\ISOs\ubuntu-24.04-live-server-amd64.iso"
Set-VMFirmware -VMName WAZUH -FirstBootDevice (Get-VMDvdDrive -VMName WAZUH)
```
> ISO Ubuntu Server: descargar a `C:\Lab\ISOs\` (borrar tras instalar, como con los otros ISOs).

## 2. Ventana de internet SOLO para instalar
El manager necesita bajar paquetes. Darle salida temporal con un segundo conmutador:
```powershell
# Opcion A (recomendada): segunda NIC en Default Switch solo durante la instalacion
Add-VMNetworkAdapter -VMName WAZUH -SwitchName "Default Switch"
```
Al terminar la instalacion + indexacion de reglas:
```powershell
Remove-VMNetworkAdapter -VMName WAZUH -Name "Adaptador de red"   # quitar la NIC de internet
# Queda solo la NIC de LAB-Net -> lab aislado de nuevo
```

## 3. Instalar Ubuntu + IP estatica en LAB-Net
- Instalar Ubuntu Server (mínimo, OpenSSH on).
- Configurar la NIC de LAB-Net con IP estática (netplan), **sin gateway** (aislada):
  ```yaml
  # /etc/netplan/99-lab.yaml
  network:
    version: 2
    ethernets:
      eth0:            # la NIC conectada a LAB-Net
        addresses: [10.10.10.20/24]
        nameservers: { addresses: [10.10.10.10] }   # DNS = DC01
  ```
  `sudo netplan apply`

## 4. Instalar Wazuh all-in-one
```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
# Al final imprime la password de 'admin'. Guardarla.
sudo tar -O -xvf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt | grep -A1 admin
```
Dashboard: `https://10.10.10.20`  (usuario `admin`).

## 5. Desplegar agentes en DC01 y WIN11 (por PowerShell Direct, sin red)
Descargar el MSI del agente (en el host, con internet) y copiarlo a cada VM, o instalar con variables:
```powershell
# Ejemplo para WIN11 (repetir para DC01). WAZUH_MANAGER apunta al manager en LAB-Net.
$cred = Get-Credential   # WIN11\labadmin  /  CORP\Administrator para DC01
Invoke-Command -VMName WIN11 -Credential $cred -ScriptBlock {
  msiexec.exe /i C:\Temp\wazuh-agent.msi /q `
    WAZUH_MANAGER="10.10.10.20" WAZUH_AGENT_NAME="WIN11"
  Start-Service WazuhSvc
}
```
> Copiar el MSI a la VM con `Copy-VMFile -VMName WIN11 -SourcePath ... -DestinationPath C:\Temp\ -FileSource Host -CreateFullPath`.

## 6. Activar la ingesta de eventchannels
En cada agente, añadir los bloques de [`agent/windows-eventchannel.conf`](agent/windows-eventchannel.conf) a
`C:\Program Files (x86)\ossec-agent\ossec.conf` y `Restart-Service WazuhSvc`.

## 7. Cargar nuestras reglas en el manager
```bash
sudo cp local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```
Verificar que cargan sin error: `sudo /var/ossec/bin/wazuh-logtest` (pegar un evento de prueba).

## 8. Quitar el internet temporal (paso 2) → lab aislado otra vez.

## 9. Validar end-to-end (disparar alertas reales)
Re-ejecutar el simulador de ataques del Proyecto 3 contra el lab:
```powershell
# desde el host
& "..\projects\03-detection-engineering\tests\Invoke-DetectionTests.ps1"
```
Y comprobar en el dashboard Wazuh → **Threat Hunting / Security Events / MITRE ATT&CK**:
- Kerberoasting honeypot (rule 100110) al pedir un TGS de `svc_sql`.
- PowerShell 4104 ofuscado (100120), tamper Defender (100130), LOLBin (100150-152).
- AS-REP (100140) requiere disparo real con KALI/Rubeus (diferido).

---

## Afinado de campos (si una regla no dispara)
1. Provoca el evento y míralo crudo en el dashboard (*Events → expandir → JSON*).
2. Comprueba el nombre exacto bajo `data.win.eventdata.*` (p.ej. `serviceName` vs `ServiceName`).
3. Ajusta el `<field name="win.eventdata.XXX">` en `local_rules.xml` y `wazuh-logtest`.

## Apagar para ahorrar recursos
`WAZUH` solo necesita estar encendida cuando cazas/validas. Para liberar RAM: `Stop-VM WAZUH`.
