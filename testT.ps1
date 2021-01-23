auditpol /set /category:"Account Logon" /subcategory:"Credential Validation" /failure:enable /success:disable
auditpol /set /category:"Account Logon" /subcategory:"Other Account Logon Events" /failure:enable /success:enable

auditpol /set /category:"Account Management" /subcategory:"Other Account Management Events" /failure:enable /success:enable
auditpol /set /category:"Account Management" /subcategory:"Security Group Management" /failure:enable /success:enable
auditpol /set /category:"Account Management" /subcategory:"User Account Management" /failure:enable /success:enable

auditpol /set /category:"Logon/Logoff" /subcategory:"Account Lockout" /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff" /subcategory:"Logoff" /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff" /subcategory:"Other Logon/Logoff Events" /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff" /subcategory:"Special Logon" /failure:enable /success:enable

auditpol /set /category:"Object Access" /subcategory:"Kernel Object" /failure:enable /success:enable
auditpol /set /category:"Object Access" /subcategory:"Other Object Access Events" /failure:enable /success:enable
auditpol /set /category:"Object Access" /subcategory:"Registry" /failure:enable /success:enable
auditpol /set /category:"Object Access" /subcategory:"SAM" /failure:enable /success:disable

auditpol /set /category:"Policy Change" /subcategory:"Audit Policy Change" /failure:enable /success:enable
auditpol /set /category:"Policy Change" /subcategory:"Authentication Policy Change" /failure:enable /success:enable
auditpol /set /category:"Policy Change" /subcategory:"Authorization Policy Change" /failure:enable /success:enable
auditpol /set /category:"Policy Change" /subcategory:"Other Policy Change Events" /failure:enable /success:enable

auditpol /set /category:"Privilege Use" /subcategory:"Audit Non Sensitive Privilege use" /failure:enable /success:enable
auditpol /set /category:"Privilege Use" /subcategory:"Other Privilege use events" /failure:enable /success:enable
auditpol /set /category:"Privilege Use" /subcategory:"sensitive Privilege use" /failure:enable /success:enable

auditpol /set /category:"System" /subcategory:"Other System Events" /failure:enable /success:enable
auditpol /set /category:"System" /subcategory:"Security System Extension" /failure:enable /success:enable
auditpol /set /category:"System" /subcategory:"System Integrity" /failure:enable /success:disable
