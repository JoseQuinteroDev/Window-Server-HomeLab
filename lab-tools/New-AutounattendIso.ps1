<#
.SYNOPSIS  Empaqueta una carpeta (con autounattend.xml en su raiz) en un ISO de arranque-respuesta.
.DESCRIPTION
    Usa IMAPI2 (COM nativo de Windows, sin ADK/oscdimg) + un helper C# para volcar el IStream a fichero.
    Windows Setup busca autounattend.xml en la raiz de medios extraibles (un DVD), por eso lo metemos en ISO.
.PARAMETER SourceDir  Carpeta cuyo contenido va a la raiz del ISO (debe contener autounattend.xml).
.PARAMETER OutIso     Ruta del ISO de salida.
.EXAMPLE  .\New-AutounattendIso.ps1 -SourceDir C:\Lab\unattend -OutIso C:\Lab\autounattend.iso
.NOTES    Lab SOC Blue Team.
#>
param(
    [Parameter(Mandatory)][string]$SourceDir,
    [Parameter(Mandatory)][string]$OutIso
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path (Join-Path $SourceDir 'autounattend.xml'))) { throw "No hay autounattend.xml en $SourceDir" }
if (Test-Path $OutIso) { Remove-Item $OutIso -Force }

# Helper C# para copiar el IStream del resultado IMAPI2 a un fichero (sin /unsafe, via Marshal)
if (-not ('ISOFileWriter' -as [type])) {
    $cs = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public class ISOFileWriter {
    public static void Create(string Path, object Stream, int BlockSize, int TotalBlocks) {
        IStream i = Stream as IStream;
        FileStream o = File.OpenWrite(Path);
        byte[] buf = new byte[BlockSize];
        IntPtr pcb = Marshal.AllocHGlobal(4);
        try {
            while (TotalBlocks-- > 0) {
                i.Read(buf, BlockSize, pcb);
                int read = Marshal.ReadInt32(pcb);
                o.Write(buf, 0, read);
            }
            o.Flush();
        } finally { o.Close(); Marshal.FreeHGlobal(pcb); }
    }
}
'@
    Add-Type -TypeDefinition $cs
}

$fsi = New-Object -ComObject IMAPI2FS.MsftFileSystemImage
$fsi.FileSystemsToCreate = 3        # ISO9660 (1) + Joliet (2)
$fsi.VolumeName = 'UNATTEND'
$fsi.Root.AddTree($SourceDir, $false)   # $false => el CONTENIDO va a la raiz
$res = $fsi.CreateResultImage()
[ISOFileWriter]::Create($OutIso, $res.ImageStream, $res.BlockSize, $res.TotalBlocks)
Write-Output ("ISO creado: {0} ({1:N0} KB)" -f $OutIso, ((Get-Item $OutIso).Length/1KB))
