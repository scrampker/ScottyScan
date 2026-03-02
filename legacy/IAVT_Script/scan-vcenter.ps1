# Connect if not already connected
Connect-VIServer -Server "192.168.101.221" -User "sscott@infowerks.com"

$timestamp  = Get-Date -Format "yyyyMMdd-HHmmss"
$exportPath = ".\output_reports\vsphere_vmlist_$timestamp.csv"

Get-VM | ForEach-Object {
    $vm      = $_
    $vmguest = Get-VMGuest -VM $vm -ErrorAction SilentlyContinue
    $vmView  = $vm | Get-View
    $hostRef = $vmView.Runtime.Host
    $vmhost  = if ($hostRef) { (Get-View -Id $hostRef).Name } else { "" }

    [pscustomobject]@{
        Name        = $vm.Name
        PowerState  = $vm.PowerState
        VMHost      = $vmhost
        vCPU        = $vm.NumCPU
        MemoryGB    = [math]::Round($vm.MemoryGB,0)
        Hostname    = $vmguest.HostName
        IPAddresses = ($vmguest.IPAddress -join ',')
        Notes       = $vm.ExtensionData.Config.Annotation
    }
} | Export-Csv -Path $exportPath -NoTypeInformation -Encoding UTF8

Write-Host "VM list exported to $exportPath"
