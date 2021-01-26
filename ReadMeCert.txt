Welcome to ReadMe.txt ReadMeCert.txt for Certificate tools.

Disclaimer:  Use these tools at your own choosing and risk.

CertificateToolsV1.txt is provided if your organization is uncomfortable with transfering in .ps1 files.

Certificate tools provide for crude certificate monitoring and centralized notification on Certificate issues:
      What certificates are coming to expiry?
      What quality of certificates you might have?
      What issuing entities are you currently connected with?

These watch functions can be programmed into ShortCuts or ScheduledTasks like: 
%systemroot%\System32\WindowsPowerShell\v1.0\powershell.exe -executionpolicy Bypass -Windowstyle Hidden -file "<FullPath>\CertificateToolsV1.ps1" ExpCert
	Recommended for this would be to run once every 40 or 60 days.

Configuration of your email SMTP connection is required in the file CertNotice.csv
Provision of your email credential may be required and can go into the CertMailP.txt file.  DO NOT use PlainTEXT.  CMS encryption or at least securestring whoudl be considered.

You will see a HashProfile<Date-Time>.txt that has Hash value confirmations of the untampered file in this project.
	Independantly you will see this same file published at https://web.ncf.ca/bv178/HashChecks.html
Hash Confirmations only provide comfort to mitigate tampering.