Import-Module BitsTransfer
#$url = "https://raw.githubusercontent.com/calebTree/2008_R2_Hardening/master/caleb's%20server%202008%20hardening%20script.ps1?token=AAUO6ZQHAMEJXAFDI4FXM726B7ES4"
#$url = "https://bit.ly/39EmNKI"
#$url = "https://bit.ly/36pOxB0"
#$url = "https://bit.ly/2Qnjznf"
#$url = "https://bit.ly/39ELmXR"
$url = "https://bit.ly/2SRNwh8"
$output = "$env:userprofile\desktop\W08R2Harden.ps1"
Start-BitsTransfer -Source $url -Destination $output
. $env:userprofile\desktop\W08R2Harden.ps1
