#Get TLS workin
[Net.ServicePointManager}::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#splunkfw7.3.8
Invoke-WebRequest -Uri "https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=windows&version=7.3.8&product=universalforwarder&filename=splunkforwarder-7.3.8-bdc98854fc40-x64-release.msi&wget=true"-OutFile C:\Users\Administrator\Desktop\splunkforwarder-7.3.8-bdc98854fc40-x64-release.msi 
#splunkfw8.1.0.1
Invoke-WebRequest -Uri "https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=windows&version=8.1.0.1&product=universalforwarder&filename=splunkforwarder-8.1.0.1-24fd52428b5a-x64-release.msi&wget=true"-OutFile C:\Users\Administrator\Desktop\splunkforwarder-8.1.0.1-24fd52428b5a-x64-release.msi 
