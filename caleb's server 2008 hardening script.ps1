<# --------- Self-elevate the script if required ---------
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}
#>

# --------- create output directory on desktop ---------
function makeOutDir{
if(-not (Test-Path -LiteralPath $env:USERPROFILE\desktop\Script_Output)){
Write-Host -ForegroundColor Green "Creating the output directory `"Script_Output`" on the desktop`n"
New-Item -Path "$env:USERPROFILE\desktop\Script_Output" -ItemType Directory | Out-Null
New-Item -Path "$env:USERPROFILE\downloads\tools" -ItemType Directory | Out-Null
New-Item -Path "$env:USERPROFILE\downloads\updates" -ItemType Directory | Out-Null
}
else{
Write-Host -ForegroundColor DarkGray "`n`"Script_Output`" already exists"
}
$host.UI.RawUI.foregroundcolor = "white"
}
# --------- downloads relevant tools ---------
function downloadTools{
    makeOutDir
    Write-Host -ForegroundColor Green "`nDownloading relevant tools"
    Write-Host -ForegroundColor Cyan "Importing BitsTransfer"
    Import-Module BitsTransfer    
    #master tools list
    $downloads = @{
        winSCP_exe = "https://cdn.winscp.net/files/WinSCP-5.15.9-Setup.exe?secure=crToMdPESi8axxxbub8Y0Q==,1579143049"
        malwarebytes_exe = "https://downloads.malwarebytes.com/file/mb-windows"
        firefox_installer_exe = "https://mzl.la/35e3KDv"
        Sysinternals_suite_zip = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
        mbsacli_2_1_1_msi = "https://download.microsoft.com/download/A/1/0/A1052D8B-DA8D-431B-8831-4E95C00D63ED/MBSASetup-x64-EN.msi" #baseline security analyzer
        fciv_exe = "http://download.microsoft.com/download/c/f/4/cf454ae0-a4bb-4123-8333-a1b6737712f7/windows-kb841290-x86-enu.exe" #hash tool
        nmap_exe = "https://nmap.org/dist/nmap-7.80-setup.exe"
        npcap_exe = "https://nmap.org/npcap/dist/npcap-0.9986.exe"
        gmer_zip = "http://www2.gmer.net/gmer.zip" #malware tool
        sublime_exe = "https://download.sublimetext.com/Sublime%20Text%20Build%203211%20x64%20Setup.exe" #text editor
        #bccrypto_zip = "https://www.bouncycastle.org/csharp/download/bccrypto-csharp-1.8.5-bin.zip"
        new_ctm_krb_zip = "https://gallery.technet.microsoft.com/Reset-the-krbtgt-account-581a9e51/file/142338/1/New-CtmADKrbtgtKeys.zip" #kerberos reset ps script
        #encryption_examples_zip = "https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Encryption-45709b87/file/108341/2/EncryptionExamples.zip"
        #protectedData_zip = "https://gallery.technet.microsoft.com/scriptcenter/Share-encrypted-data-2f91fd3f/file/129591/1/ProtectedData.zip"
        #PSBouncyCastle_psm1 = "https://raw.githubusercontent.com/rlipscombe/PSBouncyCastle/master/PSBouncyCastle.psm1"
        #file_crypt_psm1 = "https://gallery.technet.microsoft.com/EncryptDecrypt-files-use-65e7ae5d/file/165403/14/FileCryptography.psm1"
        EMET_msi = "https://download.microsoft.com/download/F/3/6/F366901C-F3CB-4A94-B377-5611740B8B19/EMET%20Setup.msi" #Enhanced Mitigation Experience Toolkit 
        dotNet_4_5_exe = "https://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_setup.exe"
        WMF_5_1_zip = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip" #Windows Managment Framework 5.1 (PS 5.1)
        #NetCease_zip = "https://gallery.technet.microsoft.com/Net-Cease-Blocking-Net-1e8dcb5b/file/165596/1/NetCease.zip" # prevents unprivileged session enumeration
        seven_ZIP_exe = "https://www.7-zip.org/a/7z1900-x64.exe"
    }
    #remove what has already been downloaded from database
    $files = Get-ChildItem "$env:userprofile\downloads\tools"
    try {$files = Foreach ($tool in $files.GetEnumerator()){$tool.Name}}
    catch [System.Management.Automation.RuntimeException]{Write-host -ForegroundColor Cyan "The `"%userprofile%\downloads\tools`" folder is empty."}
    $tool_list = $files -replace '\.', '_' #'(?m).{4}$','' - '_(?!.*_)', '.' 
    foreach($tool in $tool_list){$downloads.Remove($tool)}
    $host.UI.RawUI.foregroundcolor = "darkgray"
    $downloads
    #download all?
    $host.UI.RawUI.foregroundcolor = "magenta"
    $yes = Read-Host "Would you like to download all above" $downloads.count "tools now? (y, n)"
    $host.UI.RawUI.foregroundcolor = "cyan"
    if ($yes -eq 'y'){
        #download loop
        foreach ($key in $downloads.GetEnumerator()) {
            "Downloading $($key.Name) from $($key.Value)"
            $filename = $($key.Name)
            $url = $downloads.$filename
            $filename = $filename -replace '_(?!.*_)', '.' #Lookahead and Lookbehind Zero-Length Assertions
            $output = "$env:USERPROFILE\downloads\tools\$filename"           
            try{Start-BitsTransfer -Source $url -Destination $output}
            catch{
                $host.UI.RawUI.foregroundcolor = "red"
                Write-Host "An error occurred:"
                Write-Host $_
            }
        }
        Write-Host "All relevant tools downloaded"
    }    
    #install sublime text editor?
    function installSublime{
        if(Test-Path -Path "$env:USERPROFILE\downloads\tools\sublime.exe"){
            $host.UI.RawUI.foregroundcolor = "magenta"
            $yes = Read-Host "Would you like to install Sublime Text Editor now? (y, n)"
            if ($yes -eq 'y'){
                if(Test-Path -Path "C:\Program Files\Sublime Text 3"){
                    Write-Host "Sublime is already installed"
                } 
                else{
                    $host.UI.RawUI.foregroundcolor = "cyan"
                    Write-Host "Installing Sublime Text and adding context menue"
                    cmd /c %userprofile%\downloads\tools\sublime.exe /verysilent
                    REG ADD "HKCR\*\shell\Open with Sublime Text\command" /t REG_SZ /d "C:\Program Files\Sublime Text 3\sublime_text.exe \"%1\""
                }
            }
        }else{Write-Host -ForegroundColor Cyan "Sublime has not been downloaded yet"}
    }
    #install SP1?
    function installSP1{
        $host.UI.RawUI.foregroundcolor = "magenta"
        $yes = Read-Host "windows6.1-KB976932-X64 has been downloaded. Would you like to install SP1 now? (y, n)"
        if ($yes -eq 'y'){
            $host.UI.RawUI.foregroundcolor = "cyan"
            Write-Host "Installing SP1"
            cmd /c C:\Users\Administrator\desktop\Script_Output\tools\windows6.1-KB976932-X64.exe /unattend /norestart
        }
    }
    #install 7-Zip($host.Version.Major -lt 3)
    function install7Zip {
        $host.UI.RawUI.foregroundcolor = "cyan"
        $path_to_exe = "$env:userprofile\downloads\tools\seven_ZIP.exe"
        $path_to_installed = "C:\Program Files\7-Zip"
        if($host.Version.Major -lt 3){
            if(!(Test-Path -LiteralPath $path_to_exe) -and !(Test-Path -Path $path_to_installed)){
                Write-Host "7-Zip has not been downloaded yet." -NoNewline
                Write-Host -ForegroundColor Magenta " Would you like to download it now? (y, n): " -NoNewline
                $yes = Read-Host
                if($yes -eq 'y'){
                    $source = "https://www.7-zip.org/a/7z1900-x64.exe"
                    $destination = "$env:USERPROFILE\downloads\tools\seven_ZIP.exe"
                    Write-Host "Downloading seven_ZIP.exe from $source"
                    Start-BitsTransfer -Source $source -Destination $destination
                }else{return}
            }
            if(!(Test-Path -LiteralPath $path_to_installed) -and (Test-Path -LiteralPath $path_to_exe)){
                Write-Host -ForegroundColor Cyan "7-Zip has been downloaded but is not installed. " -NoNewline
                Write-Host -ForegroundColor Magenta "Would you like to install it now? (y, n): " -NoNewline
                $yes = Read-Host 
                if ($yes -eq 'y'){
                    $host.UI.RawUI.foregroundcolor = "cyan"
                    Write-Host "Installing 7-Zip"
                    cmd /c C:\Users\Administrator\downloads\tools\seven_ZIP.exe /S
                    Write-Host "Setting 7-Zip machine path variable"
                    #Set-Variable "PATH=%PATH%;C:\Program Files\7-Zip"
                    setx PATH "$env:path;C:\Program Files\7-Zip"
                }
            }else{Write-Host "7-Zip is already installed"}
        }else{Write-Host "7-Zip Is not required. Use `"Expand-Archive`" CmdLet"}
    }
    #install Sysinternals
    function installSysinternals {
        #extract with 7-zip
        if(!(Test-Path -Path "C:\Tools")) {
            $sys_zip_path = "$env:userprofile\downloads\tools\Sysinternals_suite.zip"
            $7z_installed = "C:\Program Files\7-Zip"
            if(!(Test-Path -Path $sys_zip_path)){
                Write-Host "`"Sysinternals_suite.zip`" has not been downloaded yet. " -NoNewline
                Write-Host -ForegroundColor magenta "Would you like to download it now? (y, n): " -NoNewline
                $yes = Read-Host
                if($yes -eq 'y'){
                    $source = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
                    Write-Host "Downloading `"Sysinternals_suite.zip`" from $source"
                    Start-BitsTransfer -Source $source -Destination $sys_zip_path
                } else{return}
            }if(Test-Path -Path $sys_zip_path){
                Write-Host -ForegroundColor Cyan "Sysinternals_suite.zip is downloaded but not installed. " -NoNewline
                Write-Host -ForegroundColor Magenta "Would you like to extract it to `"C:\Tools`" now? (y, n): " -NoNewline
                $yes = Read-Host
                if($yes -eq 'y'){
                    #install7Zip               
                    if($host.Version.Major -lt 3){
                        if(!(Test-Path -Path $7z_installed)){
                            Write-Host -ForegroundColor Cyan "7-Zip needs to be installed in order to programatically extract Sysinternals_sute.zip. " -NoNewline
                            Write-Host -ForegroundColor Magenta "Would you like to set that up now? (y, n): " -NoNewline
                            $yes = Read-Host
                            if($yes -eq 'y'){install7Zip}else{Write-Host "Nothing is available to programatically extract Sysinternals_suite.zip"; return}
                        }
                        if(Test-Path -Path $7z_installed){
                            $host.UI.RawUI.foregroundcolor = "cyan"                          
                            Write-Host "Extracting Sysinternals to C:\Tools with 7-Zip"
                            $env:Path += ";$7z_installed"
                            cmd /c "7z e `"C:\Users\Administrator\downloads\tools\Sysinternals_suite.zip`" -o`"C:\Tools`"" | Out-Null
                            Write-Host "Adding `"C:\Tools` to machine environment path variable"
                            $env:Path += ";C:\tools"
                            cmd /c "setx /m path `"%path%;C:\tools`"" | Out-Null                          
                        }else{Write-Host "Nothing is available to programatically extract Sysinternals_suite.zip"; return}
                    }else{
                        Write-Host "Extracting Sysinternals to C:\Tools with PS CmdLet"
                        Expand-Archive -LiteralPath $sys_zip_path -DestinationPath "C:\Tools" -Force
                    }
                }
            }
        }else{Write-Host "Sysinternals is already installed to `"C:\Tools`""}
    }
    #install dotNet_4.5
    function installDotNet{
        $host.UI.RawUI.foregroundcolor = "cyan"
        if(Test-Path -Path "$env:USERPROFILE\downloads\tools\dotNet_4_5.exe"){
        Write-Host "Installing dotNet_4.5"
        cmd /c C:\Users\Administrator\desktop\Script_Output\tools\dotNet_4_5.exe /passive /showfinalerror /showrmui
        }else{Write-Host "dotNet_4.5 has not been downloaded yet"}
    }
    #install WMF_5.1
    function installWMF{   
        if(!(Test-Path -Path 'C:\Program Files\7-Zip')){
            $yes = Read-Host "7-Zip is required to programatically install WMF 5.1. Would you like to install 7-Zip now? (y, n)"           
            if($yes -eq 'y'){install7Zip}else{Write-Host "Nothing is available to programatically extract `"WMF_5_1.zip`""; return}
        }elseif(!(Test-Path -Path "$env:USERPROFILE\downloads\tools\WMF_5_1.zip")){
            $yes = Read-Host "WMF_5.1 has not been downloaded yet. Would you like to download it now? (y, n)"
            if($yes -eq 'y'){
                $source = "https://download.microsoft.com/download/6/F/5/6F5FF66C-6775-42B0-86C4-47D41F2DA187/Win7AndW2K8R2-KB3191566-x64.zip"
                Write-Host "Downloading `"WMF_5_1.zip`"" from `"$source`"""
                Start-BitsTransfer -Source $source -Destination = "$env:USERPROFILE\downloads\tools\WMF_5_1.zip"
            }
        }
        if(Test-Path -Path "$env:USERPROFILE\downloads\tools\WMF_5_1.zip"){
            Write-Host "Unzipping WMF_5_1.zip to tools\WMF_5_1"
            cmd /c "7z e `"C:\Users\Administrator\Desktop\Script_Output\tools\WMF_5_1.zip`" -o`"C:\Users\Administrator\Desktop\Script_Output\tools\WMF_5_1`""
            if(Test-Path -Path "$env:userprofile\downloads\tools\WMF_5_1\Install-WMF5.1.ps1"){
                Write-Host "Invoking the script that comes with WMF_5_1.zip"
                & "$env:userprofile\downloads\tools\WMF_5_1\Install-WMF5.1.ps1"
            }
        }
    }
    $BuildVersion = [System.Environment]::OSVersion.Version
    if($BuildVersion.Revision -eq '0'){
        if(! (Test-Path -LiteralPath $env:USERPROFILE\downloads\tools\windows6.1-KB976932-X64.exe)){
            Write-Host -ForegroundColor Cyan "windows6.1-KB976932-X64 does not exist. " -NoNewline
            Write-Host -ForegroundColor Magenta "Would you like to download SP1 R2 X64 now? (y, n): " -NoNewline
            $yes = Read-Host 
            if ($yes -eq 'y'){
                $url = "https://download.microsoft.com/download/0/A/F/0AFB5316-3062-494A-AB78-7FB0D4461357/windows6.1-KB976932-X64.exe"
                $output = "$env:USERPROFILE\downloads\tools\windows6.1-KB976932-X64.exe"
                $host.UI.RawUI.foregroundcolor = "cyan"
                Write-Host "Importing BitsTransfer module"
                Import-Module BitsTransfer
                Write-Host "Downloading `"windows6.1-KB976932-X64.exe`" from $url"
                Start-BitsTransfer -Source $url -Destination $output
                Write-Host "`"windows6.1-KB976932-X64.exe`" downloaded to Script_Output\tools"
                installSP1
            }
        }
        else{installSP1}        
        installSysinternals
        install7Zip
        installSublime
    }
    #install WMF 5.1? if SP1 and WMF not already installed
    elseif($host.Version.Major -lt 3){
        $host.UI.RawUI.foregroundcolor = "magenta"
        $yes = Read-Host "Would you like to install Windows Managemnt Framework 5.1 now? (y, n)"
        if ($yes -eq 'y'){
            installDotNet
            install7Zip
            installWMF
        }        
    }
    else{
        install7Zip
        installSysinternals
        installSublime
    }        
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- group policy tool ---------
function GPTool{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "Opening GP Tool"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Click each drop box item and make the change displayed"
    #WPF AD GUI script
    Add-Type -assembly System.Windows.Forms
    $main_form = New-Object System.Windows.Forms.Form
    $main_form.Text ='Set GPO Tool'
    $main_form.Width = 600
    $main_form.Height = 100
    $main_form.AutoSize = $true
    $Label = New-Object System.Windows.Forms.Label
    $Label.Text = "GPO Object "
    $Label.Location  = New-Object System.Drawing.Point(0,10)
    $Label.AutoSize = $true
    $main_form.Controls.Add($Label)
    $ComboBox = New-Object System.Windows.Forms.ComboBox
    $ComboBox.Width = 300
    
    #hashtable Name:Value
    $GPO_EDITS = @{
    PS_Script_Execution = "Comp Config\Policies\Administrative Templates\Windows Components\Windows PowerShell\ -> `"Turn on script execution`"
    User Config - Policies - Admin Templates - Windows Components - Windows Powershell - Turn on Script Execution `"Disabled`""
    Kerberos_Encryption = "Comp Config\Policies\Windows Settings\Security Settings\Local Policies\Security Options -> Network Security: Config encrypt types (...) Kerberos\ `"AES256`""
    X_LAN_MGR_Hash = "Comp Config\Policies\Windows Settings\Security Settings\Local Policies\Security Options -> Network Security: Do not store LAN MGR hash (...) pswd change\ `"ENABLE`""
    X_LAN_MGR_Auth = "Comp Config\Policies\Windows Settings\Security Settings\Local Policies\Security Options -> Network Security: LAN MGR Auth LVL\ `"?Refuse All`""
    Win32_Conficker = "Comp Config\Policies\Administrative Templates\Windows Components\Autoplay Policies -> Turn off Autoplay\ `"ENABLE`""
    Startup_Scripts = "Comp Config\Windows Settings\Scripts (Startup/Shutdown)`nUser Config\Windows Settings\Scripts (Startup/Shutdown)"
    Audit_Policy = "Comp Config\Policies\Windows Settings\Security Settings\Advanced Audit Policy Configuration\Audit Policies\ -> `"MANY HERE ???`""
    X_Passwd_Policy = "Windows Settings\Security Settings\Account Policies\Password Policy\ -> Store passwords using reversible encryption\ `"Disabled`", `"MANY HERE ???`""
    Add_Comp_Pol = "Computer Configuration\Windows Settings\Security Settings\Local Policies\User Rights Assignment\ -> Add workstations to Domain\ `"0`""
    Deny_User_Rights = "Comp Config\Policies\Windows Settings\Security Settings\Local Policies\User Rights Assignments\ -> `"MANY w/ Deny`""
    Restricted_Groups = "Computer Configuration\Policies\Windows Settings\Security Settings\Restricted Groups -> Remove All"
    Harden_UNC = "Computer Configuration / Administrative Templates / Network / Network Provider -> Hardened UNC Paths"
    X_Guest_Account = "Go to Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options. In the right-side pane, double click on Accounts: Guest account status."
    X_RDP = "Computer Configuration � Administrative Templates � Windows Components � Remote Desktop Services � Remote Desktop Session Host � Connections.
    Allow users to connect remotely using Remote Desktop Services (enable or disable)"
    Block_APP = "User Config - Policies - Admin Templates - System - Don't run specified Windows applications `"Enable`" powershell.exe
    Comp Config - Policies - Sec Settings - App Control Policies - AppLocker - Executable Rules `"Deny, Users, C:\Windows\System32\powershell.exe`""
    }    
    
    Foreach ($GPO in $GPO_EDITS.GetEnumerator()){$ComboBox.Items.Add($($GPO.Name)) | Out-Null}
    $ComboBox.Location = New-Object System.Drawing.Point(70,10)
    $main_form.Controls.Add($ComboBox)
    $Label2 = New-Object System.Windows.Forms.Label
    $Label2.Text = "Location:"
    $Label2.Location  = New-Object System.Drawing.Point(0,40)
    $Label2.AutoSize = $true
    $main_form.Controls.Add($Label2)
    $Label3 = New-Object System.Windows.Forms.Label
    $Label3.Text = ""
    $Label3.Location = New-Object System.Drawing.Point(50,40)
    $Label3.AutoSize = $true
    $main_form.Controls.Add($Label3)
    $Button = New-Object System.Windows.Forms.Button
    $Button.Location = New-Object System.Drawing.Size(400,10)
    $Button.Size = New-Object System.Drawing.Size(120,23)
    $Button.Text = "Check"
    $main_form.Controls.Add($Button)
    $ComboBox.Add_SelectedIndexChanged({$Label3.Text = $GPO_EDITS[$ComboBox.selectedItem]})
    #$Button.Add_Click({$Label3.Text = $GPO_EDITS[$ComboBox.selectedItem]})
    $Button2 = New-Object System.Windows.Forms.Button
    $Button2.Location = New-Object System.Drawing.Size(530,10)
    $Button2.Size = New-Object System.Drawing.Size(120,23)
    $Button2.Text = "Open gpmc.msc"
    $main_form.Controls.Add($Button2)
    $Button2.Add_Click({gpmc.msc})
    $Button3 = New-Object System.Windows.Forms.Button
    $Button3.Location = New-Object System.Drawing.Size(660,10)
    $Button3.Size = New-Object System.Drawing.Size(120,23)
    $Button3.Text = "Open secpol.msc"
    $main_form.Controls.Add($Button3)
    $Button3.Add_Click({secpol.msc})
    $main_form.ShowDialog()
    Write-Host "Ending GP tool"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- timestamp Script_Output ---------
function timeStamp {
    $host.UI.RawUI.foregroundcolor = "magenta"
    $time = Read-Host "Timestamp Script_Output? (y, n)"
    if($time -eq 'y'){
        try{
        $time = Get-Date -format 'yyyy.MM.dd-HH.mm.ss'
        Rename-Item $env:userprofile\desktop\Script_Output $env:userprofile\desktop\Script_Output_$time -Force
        }
        catch{
            Write-Error "An error occured: Make sure the Script_Output folder window is closed then run timeStamp again"
            Write-Error $_
        }
    }
}
#region Firewall
# --------- turn firewall on ---------
function turnOnFirewall{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nTurning On Firewall"
    $host.UI.RawUI.foregroundcolor = "cyan"
    netsh advfirewall set allprofiles state on
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- firewall rules ---------
function firewallRules{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nCreating firewall rules:"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Blocking RDP port 3389 IN"
    netsh advfirewall firewall add rule name="Block RDP port 3389 in" protocol=TCP dir=in localport=3389 action=block
    Write-Host "Blocking VNC port 5900 IN"
    netsh advfirewall firewall add rule name="Block VNC port 5900 in" protocol=TCP dir=in localport=5900 action=block
    Write-Host "Blocking VNC Java port 5800 IN"
    netsh advfirewall firewall add rule name="Block VNC Java port 5800 in" protocol=TCP dir=in localport=5800 action=block
    Write-Host "Blocking FTP port 20 IN"
    netsh advfirewall firewall add rule name="Block FTP port 20 in" protocol=TCP dir=in localport=20 action=block
    Write-Host "Blocking all ICMP protcol V4, and 6 (ping) IN"
    netsh advfirewall firewall add rule name="ICMP block incoming V4 echo request" protocol="icmpv4:any,any" dir=in action=block
    netsh advfirewall firewall add rule name="ICMP block incoming V6 echo request" protocol="icmpv6:any,any" dir=in action=block
    Write-Host "Allowing DNS port 53 IN and (OUT?)"
    netsh advfirewall firewall add rule name="Allow DNS port 53 in" protocol=UDP dir=in localport=53 action=allow
    #netsh advfirewall firewall add rule name="Allow DNS port 53 out" protocol=UDP dir=out localport=53 action=allow
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- firewall status ---------
function firewallStatus{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nGenerating firewall status"
    $host.UI.RawUI.foregroundcolor = "cyan"
    netsh firewall show config | Out-File $env:USERPROFILE\desktop\Script_Output\firewall_status.txt
    Write-Host "`"$env:USERPROFILE\desktop\Script_Output\firewall_status.txt`" has fireawll status"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- displays common ports file ---------
function ports{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nDisplaying common ports file"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    cmd /c more %SystemRoot%\System32\Drivers\etc\services
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
#endregion Firewall

#region Disable Services
# --------- netcease ---------
function netCease {
    param([switch]$Revert) 

    function IsAdministrator
    {
        param()
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal($currentUser)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)   
    }

    function BackupRegistryValue
    {
        param([string]$key, [string]$name)
        $backup = $name+'Backup'
        
        #Backup original Key value if needed
        $regKey = Get-Item -Path $key 
        $backupValue = $regKey.GetValue($backup, $null)
        $originalValue = $regKey.GetValue($name, $null)
        
        if (($backupValue -eq $null) -and ($originalValue -ne $null))
        {
            Set-ItemProperty -Path $key -Name $backup -Value $originalValue
        }

        return $originalValue
    }

    function RevertChanges
    {
        param([string]$key,[string]$name)
        $backup = $name+'Backup'
        $regKey = Get-Item -Path $key

        #Backup original Key value if needed
        $backupValue = $regKey.GetValue($backup, $null)
        
        Write-Host "Reverting changes..."
        if ($backupValue -eq $null)
        {
            #Delete the value when no backed up value is found
            Write-Host "Backup value is missing. cannot revert changes"
        }
        elseif ($backupValue -ne $null)
        {
            Write-Verbose "Backup value: $backupValue"
            Set-ItemProperty -Path $key -Name $name -Value $backupValue
            Remove-ItemProperty -Path $key -Name $backup
        } 
        
        Write-Host "Revert completed"
    }

    if (-not (IsAdministrator))
    {
        Write-Host "This script requires administrative rights, please run as administrator."
        return
    }

    #NetSessionEnum SecurityDescriptor Registry Key 
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity"
    $name = "SrvsvcSessionInfo"
    $SRVSVC_SESSION_USER_INFO_GET = 0x00000001

    Write-Host "NetCease 1.02 by Itai Grady (@ItaiGrady), Microsoft Advance Threat Analytics (ATA) Research Team, 2016"

    if ($Revert)
    {
        RevertChanges -key $key -name $name
        Write-Host "In order for the reverting to take effect, please restart the Server service"
        return
    }

    #Backup original Key value if needed
    $srvSvcSessionInfo = BackupRegistryValue -key $key -name $name

    #Load the SecurityDescriptor
    $csd = New-Object -TypeName System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $true,$false, $srvSvcSessionInfo,0

    #Remove Authenticated Users Sid permission entry from its DiscretionaryAcl (DACL)
    $authUsers = [System.Security.Principal.WellKnownSidType]::AuthenticatedUserSid
    $authUsersSid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $authUsers, $null
    $csd.DiscretionaryAcl.RemoveAccessSpecific([System.Security.AccessControl.AccessControlType]::Allow, $authUsersSid,$SRVSVC_SESSION_USER_INFO_GET, 0,0) 

    #Add Access Control Entry permission for Interactive Logon Sid
    $wkt = [System.Security.Principal.WellKnownSidType]::InteractiveSid
    $interactiveUsers = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
    $csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $interactiveUsers, $SRVSVC_SESSION_USER_INFO_GET,0,0)

    #Add Access Control Entry permission for Service Logon Sid
    $wkt = [System.Security.Principal.WellKnownSidType]::ServiceSid
    $serviceLogins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
    $csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $serviceLogins, $SRVSVC_SESSION_USER_INFO_GET,0,0)

    #Add Access Control Entry permission for Batch Logon Sid
    $wkt = [System.Security.Principal.WellKnownSidType]::BatchSid
    $BatchLogins = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $wkt, $null
    $csd.DiscretionaryAcl.AddAccess([System.Security.AccessControl.AccessControlType]::Allow, $BatchLogins, $SRVSVC_SESSION_USER_INFO_GET,0,0)

    #Update the SecurityDescriptor in the Registry with the updated DACL
    $data = New-Object -TypeName System.Byte[] -ArgumentList $csd.BinaryLength
    $csd.GetBinaryForm($data,0)
    Set-ItemProperty -Path $key -Name $name -Value $data
    Write-Host "Permissions successfully updated"
    Write-Host "In order for the hardening to take effect, please restart the Server service" 
}

# --------- Disable Teredo ---------
function disableTeredo{
makeOutDir
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nDisabling Teredo"
cmd /c echo Before: > desktop\Script_Output\teredo_state.txt
netsh interface teredo show state | Out-File $env:USERPROFILE\desktop\Script_Output\teredo_state.txt -Append
#$host.UI.RawUI.foregroundcolor = "darkgray"
#Get-Content $env:USERPROFILE\desktop\Script_Output\teredo_state.txt
Start-Process cmd -ArgumentList ('/k', 'echo > Desktop\Script_Output\disable_teredo.vbs set shell = CreateObject("WScript.Shell"):shell.SendKeys "netsh{ENTER}interface{ENTER}teredo{ENTER}set state disabled{ENTER}exit{ENTER}exit{ENTER}" & %userprofile%\desktop\Script_Output\disable_teredo.vbs') -Wait
cmd /c echo After: >> desktop\Script_Output\teredo_state.txt
netsh interface teredo show state | Out-File $env:USERPROFILE\desktop\Script_Output\teredo_state.txt -Append
$host.UI.RawUI.foregroundcolor = "darkgray"
Get-Content $env:USERPROFILE\desktop\Script_Output\teredo_state.txt
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "`Teredo disabled"
Write-Host "`"$env:USERPROFILE\desktop\Script_Output\teredo_state`" has teredo status"
$host.UI.RawUI.foregroundcolor = "white"
cmd /c pause
}
# --------- disable administrative shares via registry ---------
function disableAdminShares{
    Write-Host -ForegroundColor Green "`nDisabling administrative shares via registry"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    REG query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ /f AutoShareServer
    $host.UI.RawUI.foregroundcolor = "cyan"
    REG ADD HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ /v AutoShareServer /t REG_DWORD /d 0
    #script kitty-ing
    Write-Host "Running NetCease"
    netCease
    Write-Host "Restarting the `'Server`' service"
    #cmd /c "net stop server && net start server"
    #cmd /c "net start Netlogon && net start dfs"
    Stop-Service server -Force
    Start-Service dfs
    Start-Service netlogon
    Start-Service server
    Write-Host "Admin shares disabled"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\ /f AutoShareServer
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
} 
# --------- disable cached credentials via registry ---------
function miscRegedits{
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nMiscilanious settings via registry (mimikatz)"
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "Disabling cached creds"
REG ADD HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest /f UseLogonCredential
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "Enabling clear password cache after 30 sec."
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v TokenLeakDetectDelaySecs /t REG_DWORD /d 30
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /f TokenLeakDetectDelaySecs
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "restrict to NTLMv2"
reg add HKLM\System\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /f lmcompatibilitylevel
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "restrict anonymous access"
reg add HKLM\System\CurrentControlSet\Control\Lsa\ /v restrictanonymous /t REG_DWORD /d 1 /f
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query HKLM\System\CurrentControlSet\Control\Lsa\ /f restrictanonymous
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "Disallow anonymous enumeration of SAM accounts and shares"
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v restrictanonymoussam /t REG_DWORD /d 1 /f
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /f restrictanonymoussam
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "disable IE password cache"
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v DisablePasswordCaching /t REG_DWORD /d 1 /f
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /f DisablePasswordCaching
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "disableing run once"
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v DisableLocalMachineRunOnce /t REG_DWORD /d 1
$host.UI.RawUI.foregroundcolor = "darkgray"
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /f DisableLocalMachineRunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /f DisableLocalMachineRunOnce
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "Finished with reg edits"
$host.UI.RawUI.foregroundcolor = "white"
cmd /c pause
}
# --------- disable SMB1 via registry ---------
function disableSMB1{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nDisabling SMB1 and enabling SMB2"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1 -Type DWORD -Value 0 -Force
    Write-Host "SMB1 disabled via HKLM registry"
    sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi
    sc.exe config mrxsmb10 start= disabled
    Write-Host "SMB1 disabled (SMB Client)"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB2 -Type DWORD -Value 1 -Force
    Write-Host "SMB2 enabled via HKLM registry"
    sc.exe config lanmanworkstation depend= bowser/mrxsmb10/mrxsmb20/nsi
    sc.exe config mrxsmb20 start= auto
    Write-Host "SMB2 enabled (SMB Client)"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- disable RDP ---------
function disableRDP{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nDisabling RDP"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Opening System Properties dialog box. Remove all Remote Desktop Users"
    sysdm.cpl
    Write-Host "Stopping RDP Service, also UserMode Port Redirector; and disabling"
    #net stop "remote desktop services"
    Stop-Service "Remote Desktop Services" -Force
    Set-Service "TermService" -StartupType Disabled
    Set-Service "UmRdpService" -StartupType Disabled
    Write-Host "Removing RDP via registry"
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" �Value 1 �Force
    Write-Host "RDP disabled"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    reg query "HKLM\System\CurrentControlSet\Control\Terminal Server" /f fDenyTSConnections
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
function disablePrintSpooler{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nStopping Print Spooler Service; and disabling"    
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Stopping WMI Service too"    
    Stop-Service winmgmt -Force
    Stop-Service spooler -Force
    Set-Service spooler -StartupType Disabled
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
#endregion Disable Services

#region Passwords
# --------- Change AD Primary DC Mode ---------
function changeDCMode { param ( )
    Import-Module ActiveDirectory
    $pdc = Get-ADDomainController -Discover -Service PrimaryDC
    Set-ADDomainMode -Identity $pdc.Domain -Server $pdc.HostName[0] -DomainMode Windows2008R2Domain
}
# --------- Main password changer ---------
#disable reverse encryption policy then change all DC user passwords except admin and binddn
function changeP{
    #region scriptkitty
    function Confirm-CtmADPasswordIsComplex
    {
    Param(
    [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
    [string]
    $Pw
    )
        Process
        {
        $CriteriaMet = 0
        If ($Pw -cmatch '[A-Z]') {$CriteriaMet++}
        If ($Pw -cmatch '[a-z]') {$CriteriaMet++}
        If ($Pw -match '\d') {$CriteriaMet++}
        If ($Pw -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$CriteriaMet++}
        If ($CriteriaMet -lt 3) {Return $false}
        If ($Pw.Length -lt 6) {Return $false}
        Return $true
        }
    }
function New-CtmADComplexPassword 
    {
    Param(
        [Parameter(Mandatory=$false,ValueFromPipeline=$true)]
        [ValidateRange(6,127)]
        [Int]
        $PwLength=24
    )
    Process
        {
        $Iterations = 0
        Do 
            {
            If ($Iterations -ge 20) 
                {
                Write-Host "Password generation failed to meet complexity after $Iterations attempts, exiting."
                Return $null
                }
            $Iterations++
            $PWBytes = @()
            $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
            Do 
                {
                [byte[]]$Byte = [byte]1
                $RNG.GetBytes($Byte)
                If ($Byte[0] -lt 33 -or $Byte[0] -gt 126) { continue }
                $PWBytes += $Byte[0]
                } 
            While 
                ($PWBytes.Count -lt $PwLength)

            $Pw = ([char[]]$PWBytes) -join ''
            } 
        Until 
            (Confirm-CtmADPasswordIsComplex $Pw)
        Return $Pw
        }      
    }
    #endregion scriptkitty
    #Make sure $OU is accurate
    makeOutDir
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nChanging all DC user passwords"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Importing AD module"
    Import-Module ActiveDirectory
    Write-Host "Disabling creation of hashes (used in pass the hash attack)"
    reg add HKLM\System\CurrentControlSet\Control\Lsa /f /v NoLMHash /t REG_DWORD /d 1
    $host.UI.RawUI.foregroundcolor = "darkgray"
    reg query HKLM\System\CurrentControlSet\Control\Lsa /f NoLMHash
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Parsing the domain name"
    $domain = wmic computersystem get domain | Select-Object -skip 1
    $domain = "$domain".Trim()
    $domaina = "$domain".Trim() -replace '.\b\w+', ''
    $domainb = "$domain".trim() -replace '^\w+\.', ''
    Write-Host "Disabling reversible encryption"
    Set-ADDefaultDomainPasswordPolicy -Identity $domain -ReversibleEncryptionEnabled $false
    $host.UI.RawUI.foregroundcolor = "magenta"
    Write-Host "Press any key to start changing all AD user passwords . . ."; $HOST.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") | OUT-NULL
    $HOST.UI.RawUI.Flushinputbuffer()
    #Write-Host "Forcing GP update"
    #gpupdate /force
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Changing All Passwords except admin and binddn`n"
    $OU = "CN=Users, DC=$domaina, DC=$domainb"
    $users = Get-ADUser -Filter * -SearchScope Subtree -SearchBase $OU
    $admin = "CN=Administrator,CN=Users,DC=$domaina,DC=$domainb" #fully qualified name
    #$binddn = "CN=binddn,CN=Users,DC=$domaina,DC=$domainb"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    #to-do: fix when auto pass not meet complex required
    New-Variable -Name hashTable -Visibility Public -Value @{}
    foreach ($user in $users) 
    { 
        if ($user -match $admin){
        Write-Host "Skipping Administrator"
        }
        elseif ($user -match 'binddn'){
        Write-Host "Skipping binddn"
        }
        elseif ($user -match 'krbtgt'){
            #$securePassword = ConvertTo-SecureString (-join ($list + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object {[char]$_})) -AsPlainText -Force
            $securePassword = ConvertTo-SecureString (New-CtmADComplexPassword 12) -AsPlainText -Force
            Write-Host -ForegroundColor Gray "Changing the password of $user"
            Set-ADAccountPassword -Identity $user -Reset -NewPassword $securePassword
            #$securePassword = ConvertTo-SecureString (-join ($list + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object {[char]$_})) -AsPlainText -Force
            $securePassword = ConvertTo-SecureString (New-CtmADComplexPassword 12) -AsPlainText -Force
            Write-Host -ForegroundColor Gray "Changing the password of $user a second time"
            Set-ADAccountPassword -Identity $user -Reset -NewPassword $securePassword
        }
        else{
            #$securePassword = ConvertTo-SecureString (-join ($list + (65..90) + (97..122) | Get-Random -Count 12 | ForEach-Object {[char]$_})) -AsPlainText -Force
            $securePassword = ConvertTo-SecureString (New-CtmADComplexPassword 12) -AsPlainText -Force
            Write-Host "Changing the password of $user"
            Set-ADAccountPassword -Identity $user -Reset -NewPassword $securePassword
            $user = "$user".Trim() -replace '[CN=]{3}|[\,].*',''
            $encrypted = ConvertFrom-SecureString -SecureString $securePassword
            Out-File $env:userprofile\desktop\Script_Output\user_passwds_list.txt -Append -InputObject $user, $encrypted,""
            Write-Host "Adding $user to the hash table"
            $hashTable.Add($user,$encrypted)
        }
    }
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "`n`"$env:USERPROFILE\desktop\Script_Output\user_passwds_list.txt`" has list of users and passwords"
    $hashTable | Export-Clixml -Path $env:userprofile\appdata\local\securePasswords.xml
    Write-Host "`"%localappdata%\securePasswords.xml`" has AD users .xml hashtable"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}    
# --------- set the admin password ---------
function changePAdmin{
    makeOutDir
    Write-Host -ForegroundColor Green "`nChanges Admin password"
    Write-Host -ForegroundColor Cyan "Importing ActiveDirectory module"
    Import-Module ActiveDirectory
    Write-Host "Extracting the domain name"
    $domain = wmic computersystem get domain | Select-Object -skip 1
    $domain = "$domain".Trim()
    $domaina = "$domain".Trim() -replace '.\b\w+', ''
    $domainb = "$domain".trim() -replace '^\w+\.', ''
    Write-Host "Changing the admin password"
    $admin = "CN=Administrator,CN=Users,DC=$domaina,DC=$domainb"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $securePassword = Read-Host "`nEnter a new admin password" -AsSecureString
    Set-ADAccountPassword -Identity $admin -Reset -NewPassword $securePassword
    <# encrypt and export
    Write-Host -ForegroundColor Cyan "Encrypting and exporting"
    $encrypted = ConvertFrom-SecureString -SecureString $securePassword
    $admin = "$admin".Trim() -replace '[CN=]{3}|[\,].*',''
    Out-File -FilePath "$env:userprofile\desktop\Script_Output\admin_binddn_passwds.txt" -Append -InputObject $admin, $encrypted, ""
    Write-Host "desktop\Script_Output\admin_binddn_passwds.txt has changes log"
    if(Test-Path -LiteralPath $env:userprofile\appdata\local\securePasswords.xml){
        $hashtable = Import-Clixml $env:userprofile\appdata\local\securePasswords.xml
    }else{$hashtable = @{}}
    $hashTable[$admin] = $encrypted
    $hashTable | Export-Clixml -Path $env:userprofile\appdata\local\securePasswords.xml
    #>
    Write-Host -ForegroundColor Cyan "admin user password has been changed"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}    
# --------- set the binddn password ---------
function changePBinddn{
    makeOutDir
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nChanges binddn password"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Importing ActiveDirectory module"
    Import-Module ActiveDirectory
    Write-Host "Extracting the domain name"
    $domain = wmic computersystem get domain | Select-Object -skip 1
    $domain = "$domain".Trim()
    $domaina = "$domain".Trim() -replace '.\b\w+', ''
    $domainb = "$domain".trim() -replace '^\w+\.', ''
    Write-Host "Changing binddn password"
    $binddn = "CN=binddn,CN=Users,DC=$domaina,DC=$domainb"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $securePassword = Read-Host "`nEnter a new binddn password" -AsSecureString
    Set-ADAccountPassword -Identity $binddn -Reset -NewPassword $securePassword
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Encrypting and exporting"
    $encrypted = ConvertFrom-SecureString -SecureString $securePassword
    $binddn = "$binddn".Trim() -replace '[CN=]{3}|[\,].*',''
    Out-File -FilePath "$env:userprofile\desktop\Script_Output\admin_binddn_passwds.txt" -Append -InputObject $binddn, $encrypted, ""
    Write-Host "desktop\Script_Output\admin_binddn_passwds.txt has changes log"
    if(Test-Path -LiteralPath $env:userprofile\appdata\local\securePasswords.xml){
        $hashtable = Import-Clixml $env:userprofile\appdata\local\securePasswords.xml
    }else{$hashtable = @{}}
    $hashTable[$binddn] = $encrypted
    $hashTable | Export-Clixml -Path $env:userprofile\appdata\local\securePasswords.xml
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "binddn user password has been changed"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}    
# --------- enable LockoutDuration 00:40:00, LockoutObservationWindow 00:20:00, ComplexityEnabled $True, MaxPasswordAge 10.00:00:00, MinPasswordLength 12 ---------
function setPassPol{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nEnabling LockoutDuration 00:40:00, LockoutObservationWindow 00:20:00, ComplexityEnabled $True, MaxPasswordAge 10.00:00:00, MinPasswordLength 12"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Importing ActiveDirectory module"
    Import-Module ActiveDirectory
    Write-Host "Extracting domain name"
    $domain = wmic computersystem get domain | Select-Object -skip 1
    $domain = "$domain".Trim()
    Set-ADDefaultDomainPasswordPolicy -Identity $domain -LockoutDuration 00:40:00 -LockoutObservationWindow 00:20:00 -ComplexityEnabled $True -MaxPasswordAge 10.00:00:00 -MinPasswordLength 12
    Write-Host "Password policies enabled"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
#endregion Passwords

#region User Query
#--------- extract more info on pid ---------
function morePIDInfo{
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Displays more info on PID(s)"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $aPID = Read-Host "`nEnter a PID to get its properties"
    Write-Host "Displaying properties of $aPID"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    Get-WMIObject Win32_Process -Filter "processid = '$aPID'" | Select-Object *
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- enter service name for more info ---------
function serviceInfo{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "Displays more info on service by name"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $service = Read-Host "`nEnter a service name to get its properties"
    Write-Host "Displaying properties of $service"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    cmd /c sc qdescription $service
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- prompt for a KB to download ---------
function pickAKB{
    Import-Module BitsTransfer
    $applicable_KBs = Import-Clixml $env:userprofile\appdata\local\might_install.xml
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nThere are" $applicable_KBs.count "available hotfixes below. KB2489256, KB2503658, and KB2769369 installed in lab"
    $host.UI.RawUI.foregroundcolor = "darkgray"   
    $applicable_KBs   
    $host.UI.RawUI.foregroundcolor = "magenta"
    $KB = Read-Host "Enter the full KB you would like to download?"
    $url = $applicable_KBs.$KB
    $output = "$env:userprofile\downloads\updates\$KB.msu"
    try{$host.UI.RawUI.foregroundcolor = "cyan"; "Downloading $KB from " + $applicable_KBs.$KB; Start-BitsTransfer -Source $url -Destination $output}
    catch{Write-Error $KB "Is not an available KB`n"; return}
    Write-Host "$KB downloaded to `"%userprofile%\downloads\updates`""
    $host.UI.RawUI.foregroundcolor = "magenta"
    $install = Read-Host "Would you like to install that KB now? (y, n)"
    if($install -eq 'y'){
        $host.UI.RawUI.foregroundcolor = "cyan"
        Write-Host "Installing $KB"
        Start-Process wusa -ArgumentList ("$env:userprofile\downloads\updates\$KB.msu", '/quiet', '/norestart') -Wait
        $host.UI.RawUI.foregroundcolor = "white"
        Restart-Computer -Confirm
    }
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- Configure NTP ---------
function configNTP{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "Configuring NTP"
    $host.UI.RawUI.foregroundcolor = "cyan"
    #$computer = hostname
    #w32tm /config /computer:$computer /update
    $host.UI.RawUI.foregroundcolor = "white"
    ipconfig
    $host.UI.RawUI.foregroundcolor = "magenta"
    $time_source = Read-Host "`nEnter an authoritative time source `"time.cloudflare.com`" https://bit.ly/2QxHkcA?"
    $host.UI.RawUI.foregroundcolor = "white"
    w32tm /config /update /manualpeerlist:"$time_source" /syncfromflags:MANUAL
    w32tm /query /status | Out-File $env:USERPROFILE\desktop\Script_Output\NTP_status.txt
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "`"$env:USERPROFILE\desktop\Script_Output\NTP_status.txt`" has NTP status"
    reg query HKLM\System\CurrentControlSet\Services\W32Time\Parameters | Out-File -Append $env:USERPROFILE\desktop\Script_Output\NTP_status.txt
    #cmd /c "net stop w32time && net start w32time"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- NTP Stripchart ---------
function NTPStripchart{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "NTP Stripchart"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $target_ip = Read-Host 'What is the target ip address? '
    w32tm /stripchart /computer:$target_ip
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- read a password ---------
function readPasswords{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "Retreives the plaintext AD password from the encrypted password DB file"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $username = Read-Host "Enter a full username to retreive the password"
    $hashtable = Import-Clixml $env:userprofile\appdata\local\securePasswords.xml
    $PlainPassword = $hashtable."$username"
    $SecurePassword = ConvertTo-SecureString $PlainPassword
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    $host.UI.RawUI.foregroundcolor = "darkgray"
    Write-Host "The $username password is: $UnsecurePassword`n"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
#endregion User Query

#region User Edits
# --------- Set admin sensitive, password required all, remove members from Schema Admins ---------
function uniqueUserPols{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nEnabling admin sensitive, password required for all, and removing all members from Schema Admins"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Importing ActiveDirectory module"
    Import-Module ActiveDirectory
    Write-Host "`nUsers that don't require a password:"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    Get-ADUser -Filter {PasswordNotRequired -eq $true}
    Set-ADUser -Identity "CN=Administrator,CN=Users,DC=team,DC=local" -AccountNotDelegated $true
    Get-ADUser -Filter {PasswordNotRequired -eq $true} | Set-ADUser -PasswordNotRequired $false
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "All users now require a password even Guest :-)"
    Write-Host "Removing all members from 'Schema Admins' AD group"
    #Remove-ADGroupMember -Identity Schema Admins -Members Administrator -Confirm:$False
    try {
        $Groups = "Schema Admins"
        foreach ($Group in $Groups){Get-ADGroupMember -Identity $Group | Remove-ADPrincipalGroupMembership -MemberOf $Group -Confirm:$false}
        }
        catch [System.SystemException] {
            Write-Host -ForegroundColor Red "An error occurred: Schema Admins group is already empty"
            Write-Error $_
            $host.UI.RawUI.foregroundcolor = "white"
            cmd /c pause
            return
        }
        Write-Host "All members removed from Schema Admins group"
        $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- disable guest account ---------
function disableGuest{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nDisabling guest account"        
    $host.UI.RawUI.foregroundcolor = "cyan"
    #Import-Module ActiveDirectory
    #Disable-ADAccount -Identity Guest
    net user guest /active:no
    Write-Host "Guest account disabled"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
#endregion User Edits

#region File System
# --------- sets script extensions to open notepad ---------
function scriptToTxt{param([switch]$Revert)
    if($Revert){
        Write-Host -ForegroundColor Green "`nReverting script extensions association to default"
        $host.UI.RawUI.foregroundcolor = "cyan"
        cmd /c assoc .bat=batfile
        cmd /c assoc .js =JSFile
        cmd /c assoc .jse=JSEFile
        cmd /c assoc .vbe=VBEFile
        cmd /c assoc .vbs=VBSFile
        cmd /c assoc .wsf=WSFFile
        cmd /c assoc .wsh=WSHFile
        $host.UI.RawUI.foregroundcolor = "white"
        cmd /c pause
    }else{
        Write-Host -ForegroundColor Green "`nAssociating script extensions to open with notepad"
        $host.UI.RawUI.foregroundcolor = "cyan"
        cmd /c assoc .bat=txtfile
        cmd /c assoc .js =txtfile
        cmd /c assoc .jse=txtfile
        cmd /c assoc .vbe=txtfile
        cmd /c assoc .vbs=txtfile
        cmd /c assoc .wsf=txtfile
        cmd /c assoc .wsh=txtfile
        $host.UI.RawUI.foregroundcolor = "white"
        cmd /c pause
    }
}
# --------- makes a backup ---------
function makeADBackup {
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nMaking a backup of the system"
    $host.UI.RawUI.foregroundcolor = "magenta"
    $location = Read-Host "Type a drive and path to backup to"
    $host.UI.RawUI.foregroundcolor = "cyan"
    wbadmin start systemstatebackup -backuptarget:$location
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
#endregion File System

#region Enumeration
# --------- order directory by date changed ---------
function dateChanged {
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nProvide files by date changed"
$host.UI.RawUI.foregroundcolor = "darkgray"
cmd /c dir /O-D /P %SystemRoot%\System32 | more
cmd /c dir /O-D /P "%appdata%" | more
$host.UI.RawUI.foregroundcolor = "white"
cmd /c pause
}
# --------- startup enumeration --------- 
function enumStartup {
    makeOutDir
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nCreating list of startup tasks"
    $host.UI.RawUI.foregroundcolor = "cyan"
    wmic startup list full | Out-File $env:USERPROFILE\desktop\Script_Output\startup_programs.txt
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run  | Out-File $env:USERPROFILE\desktop\Script_Output\startup_programs.txt -Append
    reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce  | Out-File $env:USERPROFILE\desktop\Script_Output\startup_programs.txt -Append
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run  | Out-File $env:USERPROFILE\desktop\Script_Output\startup_programs.txt -Append
    reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce  | Out-File $env:USERPROFILE\desktop\Script_Output\startup_programs.txt -Append
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "`"$env:USERPROFILE\desktop\Script_Output\startup_programs.txt`" has list of startup programs"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}
# --------- format netstat -abno --------- 
function formatNetstat{
    makeOutDir
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nRunning netstat -abno and formatting"
    $host.UI.RawUI.foregroundcolor = "cyan"
    $netstat = (netstat -abno | Select-Object -skip 2) -join "`n" -split "(?= [TU][CD]P\s+(?:\d+\.|\[\w*:\w*:))" |
    ForEach-Object {$_.trim() -replace "`n",' ' -replace '\s{2,}',',' -replace '\*:\*', '*:*,' -replace 'PID', 'PID,Ownership_Info'} | ConvertFrom-Csv
    #create ESTABLISHED and LISTENING netstat files list with only unique PIDs
    Write-Host "Creating ESTABLISHED netstat list file"
    $netstat_est = $netstat | Where-Object {$_.State -eq 'ESTABLISHED'} | Select-Object -Expand PID | Sort-Object | Get-Unique | ForEach-Object {Set-Variable -Name c -Value $_ -PassThru} |
    ForEach-Object {Get-WmiObject Win32_Process -Filter "ProcessID = '$c'" | Select-Object ProcessID,Name,Path}
    $netstat_est = ($netstat_est | Out-String).trim() -replace '(?m)^\s{30}', ''
    $netstat_est | Out-File $env:USERPROFILE\desktop\Script_Output\netstat_est.txt
    Write-Host "`"$env:USERPROFILE\desktop\Script_Output\netstat_est.txt`" has ESTABLISHED netstat"
    Write-Host "Creating LISTENING netstat list file"
    $netstat_lsn = $netstat | Where-Object {$_.State -eq 'LISTENING'} | Select-Object -Expand PID | Sort-Object | Get-Unique | ForEach-Object {Set-Variable -Name c -Value $_ -PassThru} |
    ForEach-Object {Get-WmiObject Win32_Process -Filter "ProcessID = '$c'" | Select-Object ProcessID,Name,Path}
    $netstat_lsn = ($netstat_lsn | Out-String).trim() -replace '(?m)^\s{30}', ''
    $netstat_lsn | Out-File $env:USERPROFILE\desktop\Script_Output\netstat_lsn.txt
    Write-Host "`"$env:USERPROFILE\desktop\Script_Output\netstat_lsn.txt`" has LISTENING netstat"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}

# --------- create list of running services file on desktop ---------
function runningServices{
    makeOutDir
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nCreating list of running services"
    $host.UI.RawUI.foregroundcolor = "cyan"
    Get-Service | Where-Object {$_.Status -eq "Running"} | Out-File $env:USERPROFILE\desktop\Script_Output\running_services.txt
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "`"$env:USERPROFILE\desktop\Script_Output\running_services.txt`" has list of running services"
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}

# --------- enumerate HotFix updates ---------
function hotFixCheck{
    makeOutDir
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "`nComparing systeminfo HotFix list against HotFix master-list"
    #manual page
    #$manual_KBs = @{KB4012213 = "http://support.microsoft.com/kb/4012213"}

    #compare systeminfo to KB hashtable master list
    $host.UI.RawUI.foregroundcolor = "cyan"
    $system_info = systeminfo
    $host.UI.RawUI.foregroundcolor = "darkgray"    
    if(($system_info | Out-String).Contains("x64-based PC")){
        if(($system_info | Out-String).Contains("R2")){
            if(($system_info | Out-String).Contains("Service Pack 1")){ #Windows Server 2008 R2 64-bit (6.1) SP1
                Write-Host "The system is 64-bit 6.1 and SP1 is installed"
                $auto_download_KBs = @{
                    #KB975517 = "https://bit.ly/2rArzrt" # 6.0 x86
                    KB2393802 = "http://bit.ly/2kodsxw" # after SP1
                    KB3006226 = "http://bit.ly/2jLUmzu" # after SP1
                    KB3000869 = "http://bit.ly/2kxFGZk" # after SP1
                    KB3000061 = "http://bit.ly/2k4FRHV" # after SP1
                    KB2984972 = "http://bit.ly/2l6dBFP" # after SP1
                    KB3126593 = "http://bit.ly/2jN0x6n" # after SP1
                    KB2982378 = "https://bit.ly/39o5fTa" # after SP1
                    KB3042553 = "https://download.microsoft.com/download/9/6/0/96092B3C-20B0-4D15-9C0A-AD71EC2FEC1E/Windows6.1-KB3042553-x64.msu" # after SP1
                    KB2562485 = "https://download.microsoft.com/download/8/F/6/8F6409C8-CA14-411D-B9EE-71D063FA6912/Windows6.1-KB2562485-x64.msu" # after SP1
                    KB3100465 = "https://bit.ly/2F2usVm" # after SP1
                    KB3019978 = "https://download.microsoft.com/download/A/9/2/A9261883-EDDB-4282-9028-25D3A73BFAA8/Windows6.1-KB3019978-x64.msu" # after SP1
                    KB3060716 = "https://download.microsoft.com/download/B/5/9/B5918CCD-E699-4227-98D0-88E6F0DFAC75/Windows6.1-KB3060716-x64.msu" # after SP1
                    KB3071756 = "https://download.microsoft.com/download/B/6/0/B603CE22-B0D7-48C8-83D2-3ED3FCA5365B/Windows6.1-KB3071756-x64.msu" # after SP1
                    #KB947821 = "https://download.microsoft.com/download/4/7/B/47B0AC80-4CC3-40B0-B68E-8A6148D20804/Windows6.1-KB947821-v34-x64.msu" # after SP1 & pre-SP1 (update readyness tool)
                    KB3004375 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2015/01/windows6.1-kb3004375-v3-x64_c4f55f4d06ce51e923bd0e269af11126c5e7196a.msu" # after SP1
                    KB3000483 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2015/01/windows6.1-kb3000483-x64_67cdef488e5dc049ecae5c2fd041092fd959b187.msu" # after SP1
                    KB3011780 = "http://download.windowsupdate.com/c/msdownload/update/software/secu/2014/11/windows6.1-kb3011780-x64_fdd28f07643e9f123cf935bc9be12f75ac0b4d80.msu" # after SP1
                    KB2871997 = "https://download.microsoft.com/download/E/E/6/EE61BDFF-E2EA-41A9-AC03-CEBC88972337/Windows6.1-KB2871997-v2-x64.msu" # after SP1
                    KB2931356 = "https://download.microsoft.com/download/8/C/2/8C2D99DA-306D-4CC0-88C7-DCFD81820CCE/Windows6.1-KB2931356-x64.msu" # after SP1
                    KB2503658 = "http://bit.ly/2l15YDR" # *actually installed
                    KB2489256 = "http://bit.ly/2kqhe9I" # *actually installed
                    KB2769369 = "https://bit.ly/2FeeQ17" # *actually installed
                    #KB3172605 = "https://download.microsoft.com/download/C/6/1/C61C4258-305B-4A9F-AA55-57E21000FE66/Windows6.1-KB3172605-x64.msu" # didn't work in SP1 # or pre-SP1 (not security or critical at all)
                    #KB2819745 = "https://download.microsoft.com/download/3/D/6/3D61D262-8549-4769-A660-230B67E15B25/Windows6.1-KB2819745-x64-MultiPkg.msu" # PS 4.0
                }
            }
            else{ #Windows Server 2008 R2 64-bit (6.1) pre-SP1
            Write-Host "The system is 64-bit 6.1 and pre-SP1"
            $auto_download_KBs = @{
                KB2503658 = "http://bit.ly/2l15YDR" # *actually installed
                KB2489256 = "http://bit.ly/2kqhe9I" # *actually installed
                KB2769369 = "https://bit.ly/2FeeQ17" # *actually installed
                #KB947821 = "https://download.microsoft.com/download/4/7/B/47B0AC80-4CC3-40B0-B68E-8A6148D20804/Windows6.1-KB947821-v34-x64.msu" # after SP1 & pre-SP1 also didn't work (update readiness tool)
                }
            }
        }
        else{ #Windows Server 2008 64-bit (6.0)
            Write-Host "The system is 64-bit 6.0"
            $auto_download_KBs = @{
                KB2588516 = "https://bit.ly/37oIwEN"
                KB2705219 = "https://bit.ly/2ZxEGGm"
                KB2849470 = "https://bit.ly/2MG0fQ6"
                KB3011780 = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2014/10/windows6.0-kb3011780-x64_c6135e518ffd1b053f1244a3f17d4c352c569c5b.msu"
                KB4012598 = "http://download.windowsupdate.com/d/msdownload/update/software/secu/2017/02/windows6.0-kb4012598-x64_6a186ba2b2b98b2144b50f88baf33a5fa53b5d76.msu"
                KB958644 = "https://download.microsoft.com/download/0/f/4/0f425c69-4a1f-4654-b4f8-476a5b1bae1d/Windows6.0-KB958644-x64.msu"
            } 
        }
    }
    elseif(($system_info | Out-String).Contains("R2")){ #Windows Server 2008 R2 32-bit (6.1)
        Write-Host "The system is 32-bit 6.1 pre-SP1"
        $auto_download_KBs = @{
        KB2931356 = "https://download.microsoft.com/download/8/C/2/8C2D99DA-306D-4CC0-88C7-DCFD81820CCE/Windows6.1-KB2931356-x86.msu"
        }
    }
    else{ #Windows Server 2008 32-bit (6.0)
        Write-Host "The system is 32-bit 6.0"
        $auto_download_KBs = @{            
            KB975517 = "https://bit.ly/2rArzrt"
            KB4012598 = "https://bit.ly/2Q3Qjlk"
            KB3011780 = "https://bit.ly/2ZzTRPF"
            KB958644 = "https://download.microsoft.com/download/4/9/8/498e39f6-9f49-4ca5-99dd-761456da0012/Windows6.0-KB958644-x86.msu"
        }
    }

    #creates list of installed HotFixes from systeminfo, then parses just the KB from that, then removes those from $auto_download_KBs
    #if there is no match (nothing is installed) then skipps parsing the junk
    $kb_list = Foreach ($KB in $auto_download_KBs.GetEnumerator()){$KB.Name}
    $installed = $system_info | Select-String $kb_list
    if ($null -ne $installed){
        $installed = $installed -replace '(?m)^\s{27,}\[[0-9]\w\]\:\s',''
        $installed | ForEach-Object {Set-Variable -Name c -Value $_ -PassThru} | ForEach-Object {$auto_download_KBs.Remove($c)}
    }
    #export applicable list and provide output to console
    $host.UI.RawUI.foregroundcolor = "cyan"
    $auto_download_KBs | Export-Clixml -Path $env:userprofile\appdata\local\might_install.xml
    Write-Host "`"$env:userprofile\appdata\local\might_install.xml`" has list of HotFixes and thier URLs that did not match systeminfo HotFix list"
    #download and install logic
    if($auto_download_KBs.Count -gt 0){
        #remove what has already been downloaded from database
        $files = Get-ChildItem "$env:userprofile\downloads\updates"
        $files = Foreach ($KB in $files.GetEnumerator()){$KB.Name}
        $kb_list = $files -replace '(?m).{4}$',''
        foreach($kb in $kb_list){$auto_download_KBs.Remove($kb)}
        $host.UI.RawUI.foregroundcolor = "darkgray"
        $auto_download_KBs
        $host.UI.RawUI.foregroundcolor = "magenta"
        $yes = Read-Host "`nWould you like to downlad the" $auto_download_KBs.count "above HotFixes applicable to your system now? (y, n)"    
        if ($yes -eq 'y'){
            $host.UI.RawUI.foregroundcolor = "cyan"
            Write-Host "The following" $auto_download_KBs.count "hotfixes below will be downloaded."
            $host.UI.RawUI.foregroundcolor = "darkgray"
            $auto_download_KBs
            $host.UI.RawUI.foregroundcolor = "cyan"
            Write-Host "Importing BitsTransfer module"
            Import-Module BitsTransfer            
            #download loop
            foreach ($key in $auto_download_KBs.GetEnumerator()) {
                "Downloading $($key.Name) from $($key.Value)"
                $KB = $($key.Name)
                $url = $auto_download_KBs.$KB
                $output = "$env:userprofile\downloads\updates\$KB.msu"
                Start-BitsTransfer -Source $url -Destination $output
            }
            Write-Host "Downloading complete."
            #from downloaded what is still applicable to install
            $files = Get-ChildItem "$env:userprofile\downloads\updates"
            $files = Foreach ($KB in $files.GetEnumerator()){$KB.Name}
            $kb_list = $files -replace '(?m).{4}$',''
            $install = $files | Where-Object { $_ �notmatch $installed }
            $host.UI.RawUI.foregroundcolor = "darkgray"
            $install
            $host.UI.RawUI.foregroundcolor = "magenta"
            $yes = Read-Host "Would you like to install the above" $install.count "remaining HotFixes applicable to your system now? (y, n)"
            $host.UI.RawUI.foregroundcolor = "cyan"                        
            #install loop 
            if ($yes -eq 'y'){
                foreach ($f in $install){ 
                    Write-Host "Installing $f"
                    Start-Process wusa -ArgumentList ("$env:userprofile\downloads\updates\$f", '/quiet', '/norestart') -Wait
                }
                Write-Host "Finished installing updates."
            }
        } else {
            $host.UI.RawUI.foregroundcolor = "magenta"
            $pick = Read-Host "`nWould you like to pick a specific Hotfix from the list to download? (y, n)"
            if ($pick -eq 'y'){
                pickAKB
            }else{Write-Host -ForegroundColor Cyan "No updates from the database will be installed."}
        }
    }else{Write-Host "All of the HotFixes in the database applicable to your system have already been installed."}
    $host.UI.RawUI.foregroundcolor = "white"
    cmd /c pause
}

# --------- SMB status ---------
function SMBStatus{
makeOutDir
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nReg query SMB status"
$host.UI.RawUI.foregroundcolor = "cyan"
#reg query HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | ForEach-Object {Get-ItemProperty $_.pspath} | Out-File $env:USERPROFILE\desktop\Script_Output\SMB_status.txt
sc.exe qc lanmanworkstation | Out-File $env:USERPROFILE\desktop\Script_Output\SMB_status.txt -Append
$host.UI.RawUI.foregroundcolor = "darkgray"
Get-Content $env:USERPROFILE\desktop\Script_Output\SMB_status.txt
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "`"$env:USERPROFILE\desktop\Script_Output\SMB_status.txt`" has SBM status"
$host.UI.RawUI.foregroundcolor = "white"
cmd /c pause
}

# --------- provide script output to the console ---------
function readOutput{
#output netstat -abno
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nReading script output to console:`n"
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "#netstat Output:"
if(-not (Test-Path -LiteralPath $env:USERPROFILE\desktop\Script_Output\netstat_est.txt)){
$host.UI.RawUI.foregroundcolor = "darkgray"
Write-Host "run regexNetstat"
}else{
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "#ESTABLISHED Connections (netstat_est.txt)"
$host.UI.RawUI.foregroundcolor = "darkgray"
Get-Content $env:USERPROFILE\desktop\Script_Output\netstat_est.txt
Start-Sleep -s 3
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "#LISTENING Connections (netstat_lsn.txt)"
$host.UI.RawUI.foregroundcolor = "darkgray"
Get-Content $env:USERPROFILE\desktop\Script_Output\netstat_lsn.txt
}

Start-Sleep -s 3
#output running services
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "`n#List of Running Services (running_services.txt)"
$host.UI.RawUI.foregroundcolor = "darkgray"
if(-not (Test-Path -LiteralPath $env:USERPROFILE\desktop\Script_Output\running_services.txt)){
Write-Host "run runningServices"
}else{
Get-Content $env:USERPROFILE\desktop\Script_Output\running_services.txt
}

Start-Sleep -s 3
#updates to install
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "#Please attempt to install these KBs (might_install.txt):"
if(-not (Test-Path "$env:userprofile\appdata\local\might_install.xml")){
Write-host "run hotFixCheck"
}
else{
    $applicable_KBs = Import-Clixml $env:userprofile\appdata\local\might_install.xml
    $applicable_KBs | Out-File "$env:USERPROFILE\desktop\Script_Output\might_install.txt"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    Get-Content $env:USERPROFILE\desktop\Script_Output\might_install.txt
}

Start-Sleep -s 3
#NTP status
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "`n#Network Time Protocol (NTP) Status (w32tm /query /status)"
$host.UI.RawUI.foregroundcolor = "darkgray"
w32tm /query /status

Start-Sleep -s 3
#firewall status
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "#Firewall Status (firewall_status.txt)"
$host.UI.RawUI.foregroundcolor = "darkgray"
if(-not (Test-Path -LiteralPath $env:USERPROFILE\desktop\Script_Output\firewall_status.txt)){
Write-Host "run firewallStatus"
}else{
Get-Content $env:USERPROFILE\desktop\Script_Output\firewall_status.txt
}

Start-Sleep -s 3
#SMB status
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "#SMB Status (SMB_status.txt)"
$host.UI.RawUI.foregroundcolor = "darkgray"
if(-not (Test-Path -LiteralPath $env:USERPROFILE\desktop\Script_Output\SMB_status.txt)){
Write-Host "run SMBStatus"
}else{
Get-Content $env:USERPROFILE\desktop\Script_Output\SMB_status.txt
}

Start-Sleep -s 3
#Teredo status
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "`n#Teredo Status (teredo_state.txt)"
$host.UI.RawUI.foregroundcolor = "darkgray"
if(-not (Test-Path -LiteralPath $env:USERPROFILE\desktop\Script_Output\teredo_state.txt)){
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "Getting teredo state"
    $host.UI.RawUI.foregroundcolor = "darkgray"
    netsh interface teredo show state
    $host.UI.RawUI.foregroundcolor = "cyan"
    Write-Host "run disableTeredo"
}else{
    Get-Content $env:USERPROFILE\desktop\Script_Output\teredo_state.txt
}

$host.UI.RawUI.foregroundcolor = "white"
cmd /c pause
}

# --------- run enumeration functions ---------
function enumerate{
    $host.UI.RawUI.foregroundcolor = "green"
    Write-Host "Running enumeration functions"
    formatNetstat
    firewallStatus
    runningServices
    enumStartup
    hotFixCheck
    SMBStatus
    #readOutput
}
#endregion Enumeration

# --------- run all hardening functions ---------
function harden{
Write-Host -ForegroundColor Green "Hardening . . ."
makeOutDir
enumerate
turnOnFirewall
firewallRules
uniqueUserPols
disableTeredo
disableSMB1
disableRDP
disableAdminShares #also netcease
miscRegedits
disablePrintSpooler
disableGuest
changeP
changePAdmin
changePBinddn
setPassPol
scriptToTxt
downloadTools
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nOpening Task Scheduler"
taskschd.msc
$host.UI.RawUI.foregroundcolor = "cyan"
Write-Host "Manually examine scheduled tasks"
$host.UI.RawUI.foregroundcolor = "white"
cmd /c pause
GPTool
#timestamp
timeStamp
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nAll hardening functions are finished. Restart computer?"
$host.UI.RawUI.foregroundcolor = "white"
restart-computer -Confirm
}

# --------- provide list of available functions ---------
function avail{
$host.UI.RawUI.foregroundcolor = "green"
Write-Host "`nAvailable Functions:"
$host.UI.RawUI.foregroundcolor = "darkcyan"
Write-Host "
------- Noninvasive: -------
makeOutDir�(makes�script�output�directory�on�desktop)
timeStamp (timestamp Script_Output)
enumerate�(enumStartup, formatNetstat,�firewallStatus,�runningServices, hotFixCheck)
ports (displays common ports file)
downloadTools�(download�relevant�tools)
hotFixCheck (checks�list�of�HotFix�KBs�against�systeminfo)
pickAKB�(Provides�applicable�KB�info�then�prompts�for�KB�and�downloads�<KB>.msu�to�Script_Output)
autoDownloadKB�(#incomplete)
enumStartup
dateChanged
firewallStatus
SMBStatus�(returns�SMB�registry�info)
formatNetstat�(format�netstat�-abno)
runningServices
morePIDInfo�(enter�a�PID�for�more�info)
serviceInfo�(enter�a�service�name�for�more�info)
NTPStripchart
readPasswords
readOutput�(provide�function�output�to console)
avail (display this screen)
"
$host.UI.RawUI.foregroundcolor = "darkgreen"
Write-Host "
------- Invasive: -------
harden�(makeOutputDir,�turnOnFirewall,�setAssToTxt,�disableAdminShares,�miscRegedits, disableSMB1,�disableRDP,
disablePrintSpooler,�disableGuest,�changePAdmin, changePBinddn, GPTool,�changeP,�setPassPol,�uniqueUserPols,�enumerate)
scriptToTxt (script�file�type�open�with�notepad) | -Revert, -r
makeADBackup
changeDCMode (changes Domain Mode to Windows2008R2Domain)
netCease (disable Net Session Enumeration) | -Revert
GPTool (opens�GP�info�tool)
disableGuest�(disables�Guest�account)
disableRDP�(disables�RDP�via�regedit)
disableAdminShares�(disables�Admin�share�via�regedit)
miscRegedits (many mimikatz cache edits)
disablePrintSpooler (disables print spooler service)
disableTeredo��(disables�teredo)
turnOnFirewall�(turns�on�firewall)
firewallRules�(Block�RDP�In,�Block�VNC�In,�Block�VNC�Java�In,�Block�FTP�In)
disableSMB1�(disables�SMB1�and�enable�SMB2�via�registry)
configNTP�(ipconfig�+�set�NTP�server)
changeP�(Kyle's�AD�user�password�script�enhanced)
changePAdmin (input admin password)
changePBinddn (input admin password)
setPassPol�(enable�passwd�complexity�and�length�12)
uniqueUserPols�(enable�all�users�require�passwords,�enable�admin�sensitive,�remove�all�members�from�Schema�Admins)
"
$host.UI.RawUI.foregroundcolor = "darkred"
Write-Host "
------- Injects: -------
firewallStatus
configNTP
`n"
$host.UI.RawUI.foregroundcolor = "white"
}
avail

#$HOST.UI.RawUI.ReadKey(�NoEcho,IncludeKeyDown�) | OUT-NULL
#$HOST.UI.RawUI.Flushinputbuffer()

#cmd /c pause