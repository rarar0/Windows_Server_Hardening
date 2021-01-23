Disable-PSRemoting -Force
Clear-Item -Path WSMan:\localhost\Client\TrustedHosts –Force
Import-Module SeverManager
Import-Module ActiveDirectory
Add-WindowsFeature RSAT-AD-Powershell
Add-WindowsFeature Powershell-ISE

netsh advfirewall reset
netsh advfirewall set allprofile state on
netsh advfirewall firewall set rule name=all new enable=no
netsh interface teredo set state disable
netsh interface ipv6 6to4 set state state=disabled undoonstop=disabled
netsh interface ipv6 isatap set state state=disabled
netsh interface ipv4 set global mldlevel=none
netsh advfirewall set allprofiles settings unicastresponsetomulticast disable



$array1 = 389,636,3268,3269,88,53,25,135,5722,464,9389
foreach ($element in $array1)
{
netsh advfirewall firewall add rule name="TCP allow" dir=in action=allow protocol=TCP localport= 
}


$array2 = 389,88,53,123,464,138,67,2535,137
foreach ($element2 in $array2)
{
netsh advfirewall firewall add rule name="UDP allow" dir=in action=allow protocol=UDP localport= $element2
}


$array3 = "0-24","26-52","54-79","80-87","89-134","136-388","390-442","443-463","465-635","637-3267","3270-5721","5723-9388","9390-65535"
foreach ($element3 in $array3){
netsh advfirewall firewall add rule name="TCP deny" dir=in action=block protocol=TCP localport= $element3
}


$array4 = "0-52","2535-65535","54-66","68-79", "80-87","89-122","124-137","139-388","390-442","443-463","465-2534"
foreach ($element4 in $array3){
netsh advfirewall firewall add rule name="UDP deny" dir=in action=block protocol=UDP localport= $element4
}



New-ItemProperty "HKLM:\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP" -Name "UPnPMode" -Value 2 -PropertyType "DWord"

REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v "EnableLUA" /t REG_DWORD /d 1 /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 2 /f
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v "PromptOnSecureDesktop" /t REG_DWORD /d 1 /f

schtasks /delete /tn * /f

