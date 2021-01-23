auditpol /set /category:"Account Logon" /subcategory:"Audit Credential Validation" /failure:enable /success:disable
auditpol /set /category:"Account Logon" /subcategory:"Audit Other Account Logon Events" /failure:enable /success:enable

auditpol /set /category:"Account Management" /subcategory:"Audit Other Account Management Events Properties" /failure:enable /success:enable
auditpol /set /category:"Account Management" /subcategory:"Audit Security Group Management Properties" /failure:enable /success:enable
auditpol /set /category:"Account Management" /subcategory:"Audit User Account Management Properties" /failure:enable /success:enable

auditpol /set /category:"Logon/Logoff" /subcategory:"Audit Account Lockout Properties" /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff" /subcategory:"Audit Logoff Properties" /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff" /subcategory:"Audit Other Logon/Logoff Events" /failure:enable /success:enable
auditpol /set /category:"Logon/Logoff" /subcategory:"Audit Special Logon" /failure:enable /success:enable

auditpol /set /category:"Object Access" /subcategory:"Audit Kernel Object" /failure:enable /success:enable
auditpol /set /category:"Object Access" /subcategory:"Audit Other Object Access Events" /failure:enable /success:enable
auditpol /set /category:"Object Access" /subcategory:"Audit Registry" /failure:enable /success:enable
auditpol /set /category:"Object Access" /subcategory:"Audit SAM" /failure:enable /success:disable

auditpol /set /category:"Policy Change" /subcategory:"Audit Audit Policy Change" /failure:enable /success:enable
auditpol /set /category:"Policy Change" /subcategory:"Audit Authentication Policy" /failure:enable /success:enable
auditpol /set /category:"Policy Change" /subcategory:"Audit Authorization Policy Change" /failure:enable /success:enable
auditpol /set /category:"Policy Change" /subcategory:"Audit Other Policy Change Events" /failure:enable /success:enable

auditpol /set /category:"Privilege Use" /subcategory:"Audit Non-Sensitive Privilege use" /failure:enable /success:enable
auditpol /set /category:"Privilege Use" /subcategory:"Audit Other Privilege use events" /failure:enable /success:enable
auditpol /set /category:"Privilege Use" /subcategory:"Audit sensitive Privilege use" /failure:enable /success:enable

auditpol /set /category:"System" /subcategory:"Audit Other System Events" /failure:enable /success:enable
auditpol /set /category:"System" /subcategory:"Audit Security System Extension" /failure:enable /success:enable
auditpol /set /category:"System" /subcategory:"Audit System Integrity" /failure:enable /success:disable

