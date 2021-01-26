#Certificate Info Tools
<#
Find-ExpiringCerts  ### Recommendation:  Run this every 60 days
	Dflt PrepPeriod = 75 # Presumes run every 60 days
Find-ExpiringEntityCerts
	Dflt PrepPeriod = 75 # Presumes run every 60 days
 	Dflt="*Microsoft*"
Find-ExpiredCerts
Find-Certsby Algorithm
	Dflt Algorithms=("SHA1","SHA2","SHA256","SHA384","SHA512","MACTripleDES","MD5","RIPEMD60")
	Dflt Styles=("RSA","DSA","ECDSA")
Find-CertsbyEntity
 	Dflt="*Microsoft*"

Optional arguments for scheduled run or Shortcuted runs...
Args[0] one of ExpCert|ExpEntCert|ExpdCert|CertByAlgor|CertbyEnt
	If missing then the user is Prompted
Args[1] PrepPeriod in days, or string of comma separated Algorithms, Or string of comma separated Entity/Keywords
	Entity/Keywords should be preped for "*entry*" for -like comparison
Args[2] Entity Keywords or Style
#>


<# Expiring Certs - Some are kept to support previously signed SW without update #####
.Synopsis
   Provides a list of Certificates that are coming up for expiry
.Description
   Reviews the certificate store for Certificates X days from being no longer valid or current
.Parameter
   PrepPeriod  Number of days forward to look for Certificates coming to EoL Dflt=75 
        Recent expiries can be seen with a negative number of days
.Example
      Find-ExpiringCerts -PrepPeriod 7   # Expiring in next week
      Find-ExpiringCerts -PrepPeriod -7  # Expired just last week
#>
Function Find-ExpiringCerts {
     Param ($PrepPeriod = 75 )
     $tdy = Get-Date
     if ($PrepPeriod -gt 0) {     
        $StartDate = $tdy
        $EndDate = $tdy.addDays($PrepPeriod)
     }
     Else {
        $StartDate = $tdy.AddDays($prepPeriod)
        $EndDate = $tdy
     }

    $GCI = Get-ChildItem -path "cert:" -Recurse | Where-Object { ($_.notafter -gt $StartDate) -AND ( $_.notafter -le $EndDate)}
    Foreach ($certif in $GCI) {
       "$($certif.Name), $($certif.Subject), $($certif.NotAfter)"
    }
} # Function Find-ExpiringCerts

<# Expiring Entity Certs - A certain Cert is critical to know its upcoming expiry #####
.Synopsis
   Provides a list of Certificates of a specific entity that are coming up for expiry
.Description
   Reviews the certificate store for Certificates X days from being no longer valid or current
.Parameter
   PrepPeriod  Number of days forward to look for Certificates coming to EoL Dflt=75 
        Recent expiries can be seen with a negative number of days
.Parameter 
   EntityString  Like array of 1 or more company names or keyword on interest  Dflt="*Microsoft*"
.Example
      Find-ExpiringEntityCerts -PrepPeriod 7  -EntityString "*HQ-CA*"                   # Expiring in next week
      Find-ExpiringEntityCerts -PrepPeriod -7  -EntityString @("*HQ-CA*","*Microsoft*") # Expired just last week
#>
Function Find-ExpiringEntityCerts {
     Param ($PrepPeriod = 75,
            $EntityString
           )
     $tdy = Get-Date
     # Prepare the Period
     if ($PrepPeriod -gt 0) {     
        $StartDate = $tdy
        $EndDate = $tdy.addDays($PrepPeriod)
     }
     Else {
        $StartDate = $tdy.AddDays($prepPeriod)
        $EndDate = $tdy
     }
     #Prepare the entities
     $AEntityString = @()
     if ($EntityString.length -eq 0) { 
        $AEntityString += "*MicroSoft*"
        }
        else {
            if ($EntityString.Tostring().Indexof(",") -eq -1) { 
            $AEntityString += $EntityString
            }
            else {
            $AEntityString += $EntityString -split ","
            }
        }
     Foreach ($Ent in $AEntityString) {
       $GCI = Get-ChildItem -path "cert:" -Recurse | Where-Object { ($_.notafter -gt $StartDate) -AND ( $_.notafter -le $EndDate) -AND (($_.issuer -like $ent) -or ($_.subject -like $ent))}
       Foreach ($certif in $GCI) {
          "$($certif.Name), $($certif.Subject), $($certif.NotAfter)"
       } # Foreach Certif
    } # Foreach ent
} # Function Find-ExpiringEntityCerts

<# Expired Certs - Soome are kept to support previously signed SW without update #####
.Synopsis
   Provides a list of Certificates that should no longer be considered current
.Description
   Reviews the certificate store for Certificates no longer current and valid 
.Example
      Find-ExpiredCerts
#>
Function Find-ExpiredCerts {
     $tdy = Get-Date
     $GCI = Get-ChildItem -path "cert:" -Recurse | Where-Object { $_.notafter -lt $tdy}
    Foreach ($certif in $GCI) {
       "$($certif.Name), $($certif.Subject), $($certif.NotAfter)"
    } # Each Certificate
} # Function Find-ExpiredCerts

<# Identify Certificate by Hash Quality #####
SHA1,SHA2, SHA256, SHA384, SHA512, MACTripleDES, MD5, RIPEMD60
RSA,DSA,ECDSA
.Synopsis
   Provides a list of Certificates using the HASH styles of interest.  (How long are you vulnerable to weak certificates?)
.Description
   Usage:  A hash algorithm is changing.  What exosure does your cert set have to that change?
.Parameter 
   Algorithms  Pick Algorithm or Algorithms of interest Dflt=("SHA1","SHA2","SHA256","SHA384","SHA512","MACTripleDES","MD5","RIPEMD60")
.Parameter 
   Styles  Pick style or Styles of interest Dflt=("RSA","DSA","ECDSA")
.Example
   $WHOS =("*UserTrust*","*Go Daddy*","*Geotrust*","*Verisign*")
    foreach ($who in $Whos) {
      "*****WHO $who****"
      Find-CertsbyAlgorithm -Algorithms ("SHA1","SHA2")
    }
#>
Function Find-CertsbyAlgorithm {
     PARAM ( $Algorithms ,
             $Styles      )

     #Prepare the Algorithms
     if ($Algorithms.length -eq 0) { 
        $AAlgorithms = @("SHA1","SHA2","SHA256","SHA384","SHA512","MACTripleDES","MD5","RIPEMD60")
        }
        else {
            $AAlgorithms = @()
            if ($Algorithms.Tostring().Indexof(",") -eq -1) { 
            $AAlgorithms += $Algorithms
            }
            else {
            $AAlgorithms += $Algorithms -split ","
            }
        }

     #Prepare the Styles
     if ($Styles.length -eq 0) { 
        $AStyles = @("RSA","DSA","ECDSA") 
        }
        else {
            $AStyles = @()
            if ($Styles.Tostring().Indexof(",") -eq -1) { 
            $AStyles += $Styles
            }
            else {
            $AStyles += $Styles -split ","
            }
        }


  Foreach ($Algorithm in $AAlgorithms) {
   Foreach ($Style in $AStyles) {
     $AlgorName ="$Algorithm$Style"
     "******** $Algorithm $style **************"
     $GCI = Get-ChildItem -path "cert:" -Recurse | Where-Object { $_.SignatureAlgorithm.FriendlyName  -eq $AlgorName } 
     
    Foreach ($certif in $GCI) {
       $certif
       "$($certif.Name), $($certif.SignatureAlgorithm.FriendlyName), $($certif.NotAfter)"
    } # Certificate
  } # For all submitted Styles
 } # For all submitted Algorithms
} # Function Find-CertsbyAlgorithm

<#  Identify Certificates by the Entities associated #####
.Synopsis
   Provides a list of key tracking information on Certificates containing keywords or names of interest. (How long is one tied to an certificate entity?)
.Description
   Usage:  A compromise of a cert authority has been declared.  What exosure does your cert set have to that threat?
.Parameter 
   EntityString  Like array of 1 or more company names or keyword on interest  Dflt="*Microsoft*"
.Example
   $WHOS = @("*UserTrust*","*Go Daddy*","*Geotrust*","*Verisign*")
    foreach ($who in $Whos) {
      "*****WHO $who****"
      Find-CertsbyEntity -EntityString $who
    }
#>
Function Find-CertsbyEntity {
     PARAM ( $EntityString )
     #Prepare the entities
     $AEntityString = @()
     if ($EntityString.length -eq 0) { 
        $AEntityString += "*MicroSoft*"
        }
        else {
            if ($EntityString.Tostring().Indexof(",") -eq -1) { 
            $AEntityString += $EntityString
            }
            else {
            $AEntityString += $EntityString -split ","
            }
        }

   Foreach ($Ent in $AEntityString) {
    $GCI = Get-ChildItem -path "cert:" -Recurse | Where-Object { ($_.Subject  -like $Ent) -or ($_.Issuer -like $Ent) } 
    Foreach ($certif in $GCI) {
       $certif
       "$($certif.Name), $($certif.Issuer), $($certif.SignatureAlgorithm.FriendlyName), $($certif.NotAfter)"
    } # Forerach Certificate
   } # Foreach Entity
} # Function Find-CertsbyEntity

#################### TEST AREA ########################
If ($certTest -eq "TCert10") {
  $AAry = @(-30,60,90,-120,150,180)
  Foreach ($alg in $AAry) {
    "###### Expiring in $alg Days ######"
    Find-ExpiringCerts -PrepPeriod $alg
   } # Foreach time period
}

If ($certTest -eq "TCert20") {
  Find-ExpiredCerts
}

If ($certTest -eq "TCert30") {
$AAry = @("SHA1","SHA2","SHA256","SHA384","SHA512","MACTripleDES","MD5","RIPEMD60")
$ASty = @("RSA","DSA","ECDSA")

  Find-CertsbyAlgorithm -Algorithms $AAry -Styles $ASty
}

If ($certTest -eq "TCert40") {
$WHOS = @("*UserTrust*","*Go Daddy*","*Geotrust*","*Verisign*")
   foreach ($who in $Whos) {
   "*****WHO****"
   Find-CertsbyEntities -EntityString $who
   }
}

If ($certTest -eq "TCert50") {
$WHOS = @("*UserTrust*","*Go Daddy*","*Geotrust*","*Verisign*","*Microsoft*")
$PrepPeriod = 365
   foreach ($who in $Whos) {
   "*****WHO****"
   Find-ExpiringEntityCerts -EntityString $who -PrepPeriod $PrepPeriod
   }
}

If ($certTest -eq "TCert51") {    ###### Cert of interest ######
$WHOS = @("*HQ-CA*","*Microsoft*")  # What entities you are interested in 
$PrepPeriod = 65                  # How many days ahead you want to start catching these
   foreach ($who in $Whos) {
   "*****WHO****"
   Find-ExpiringEntityCerts -EntityString $who -PrepPeriod $PrepPeriod
   }
}

################## MAIN ####################
$Mach = [environment]::MachineName
$tdy = get-date -Format "yyyMMdd-HHmmss"
$ResultFile = "$PSScriptRoot\Results\CertRvw$Mach-$tdy.txt"

$RptHdr = @()

if ($($args[0].length) -eq 0) { #PROMPT for Manual Entries
    " Expiring Certificates = ExpCert [N]"
    "    PrepPeriod N default is 75, N must be integer and represents days from today"
    " Expiring Entity Certificates = ExpEndCert [N] [*ent*[,*ent*...]]"
    "    N see above"
    "    Entity/Keyword prepared for Like i.e., *Microsoft*,*Vadis*,*Daddy*"
    " Expird Certificates = ExpdCert"
    " Certificates by Algorithm = CertbyAlgor [Alg[,alg...]] [Sty[,Sty[,Sty]]]"
    "    Algorithms are SHA1,SHA2,SHA256,SHA384,SHA512,MACTripleDES,MD5,RIPEMD60"
    "    Styles are RSA,DSA,ECDSA "
    " Certificates by Entity = CertbyEnt [*ent*[,*ent*...]]"
    "    Entity/Keyword see above"

    $args = @()
    $Parm0 = read-host "Enter your choice to Run (ExpCert,ExpEntCert,ExpdCert,CertByAlgor,CertbyEnt)"
    if ($Parm0.length -eq 0)  { $args += "ExpCert" }
    else {$args += $Parm0 }
    $Parm1 = Read-host "Enter Param 1 (For default press Return)(For multiple values value coma value...)"
    if ($Parm1.length -ne 0)  { $args += $Parm1 }
    $Parm2 = Read-host "Enter Param 2 (For default press Return)(For multiple values value coma value...)"
    if ($Parm2.length -ne 0)  { $args += $Parm2 }
}

if ($args[0] -eq "ExpCert") {
   $RptHdr += "Expiring Certificates  on $Mach as at $tdy"
   $RptHdr += "Name      ,Subject    ,Expiry Date"
   $RptHdr += "========================="
   if ($args[1].length -eq 0) {
       $body = Find-ExpiringCerts
   }
   else {
       $body = Find-ExpiringCerts -PrepPeriod $args[1]
   }
}
elseif ( ($args[0] -eq "ExpEntCert") -or ($FuncRun -eq "ExpEntCert") ) { 
   $RptHdr += "Expiring Entity Certificates  on $Mach as at $tdy"
   $RptHdr += "Name      ,Subject    ,Expiry Date"
   $RptHdr += "========================="
   if ($args[1].length -eq 0) {
       $body = Find-ExpiringEntityCerts
   }
   else {
       if ($args[2].length -eq 0) {
          $body = Find-ExpiringEntityCerts -PrepPeriod $args[1]
       }
       else {
          $body = Find-ExpiringEntityCerts -PrepPeriod $args[1] -EntityString $args[2]
       }
   }
}
elseif ( ($args[0] -eq "ExpdCert") -or ($FuncRun -eq "ExpdCert") ) {   
   $RptHdr += "Expired Certificates  on $Mach as at $tdy"
   $RptHdr += "Name      ,Subject    ,Expiry Date"
   $RptHdr += "========================="
   $body = Find-ExpiredCerts
}
elseif ( ($args[0] -eq "CertbyAlgor") -or ($FuncRun -eq "CertbyAlgor") ) { 
   $RptHdr += "Certificates by Algorithm on $Mach as at $tdy"
   $RptHdr += "Name      ,Algorithm    ,Expiry Date"
   $RptHdr += "========================="
   if ($args[1].length -eq 0) {
       $body = Find-CertsbyAlgorithm
   }
   else {
       if ($args[2].length -eq 0) {
          $body = Find-CertsbyAlgorithm -Algorithms $args[1]
       }
       else {
          $body = Find-CertsbyAlgorithm -Algorithms $args[1] -Styles $args[2]
       }
   }
}
elseif ( ($args[0] -eq "CertbyEnt") -or ($FuncRun -eq "CertbyEnt") ) {    
   $RptHdr += "Certificates by Entities on $Mach as at $tdy"
   $RptHdr += "Name      ,Issuer     ,Algorithm    ,Expiry Date"
   $RptHdr += "=================================="
if ($args[1].length -eq 0) {
       $body = Find-CertsbyEntity
   }
   else {
       $body = Find-CertsbyEntity -EntityString $args[1]
   }
} # Functions Have Run
# Now record and Notify - HeartBeat this to know if you have machine missing off the list.
# Record
foreach ($Hdrline in $RptHdr){
  $Hdrline >>$ResultFile
}
$body      >>$ResultFile
# Notify
   $ICSV = Import-Csv -Delimiter "," -Path "$PSScriptRoot\CertNotice.csv" 

   $PSEmailServer = $ICSV.Server 
   $EmailID  = $ICSV.EmailID 
   $ToList   = $ICSV.To  
   $FromList = $ICSV.From
   $CCList   = $ICSV.CC
   $Port     = $ICSV.Port
   $Cert     = $ICSV.Cert
   #"$PSEmailServer,$ToList,$FromList,$Port,$EmailID"

#NOTE:  Internal SMTP servers may not require any ID Password to receive a necessary Connection 
   $userPassword = UNProtect-CMSmessage -To "$Cert" -Path "$PSScriptRoot\CertMailP.txt" 
   [securestring]$secStringPassword = ConvertTo-SecureString $userPassword -AsPlainText -Force
   [pscredential]$credObject = New-Object System.Management.Automation.PSCredential ($EmailID, $secStringPassword)
  
   If ($CCList.length -le 0) {
      Send-MailMessage -Attachments $Resultfile  -Subject "Certificate Review for $Mach on $tdy" `
         -From $FromList `
         -To $tolist -Body "Action on attached Results"`
         -SmtpServer $PSEmailServer  -Port $Port -Credential $credObject -UseSsl
      }
      Else {
       Send-MailMessage -Attachments $Resultfile  -Subject "Certificate Review for $Mach on $tdy" `
         -From $FromList `
         -To $tolist -Body "Action on attached Results"`
         -Cc $cclist `
         -SmtpServer $PSEmailServer  -Port $Port -Credential $credObject -UseSsl
      }

