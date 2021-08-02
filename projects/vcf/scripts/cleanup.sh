#!/bin/pwsh
param (
	$HostIP
)

$esxserver = Connect-VIServer -Server $HostIP -User root -Password {{ vmware_password }}
$esxcli = Get-EsxCli -VMhost (Get-VMHost $esxserver) -V2
$esxcli.network.ip.interface.remove.Invoke(@{interfacename="vmk0"})
$esxcli.network.vswitch.standard.portgroup.remove.Invoke(@{portgroupname="Management Network";vswitchname="vSwitch0"})
Get-VMHost $esxserver | Get-VirtualPortGroup -Name "management-vcf01" | Set-VirtualPortGroup -Name "Management Network"
