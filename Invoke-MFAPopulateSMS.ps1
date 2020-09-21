<#
    .SYNOPSIS
     This script is made to prepopulate all users with SMS token for MFA if they have mobile number regsistered in Azure AD   
    .DESCRIPTION
    
    .PARAMETER ClientID
    
    .PARAMETER TenantID
    
    .NOTES
        Author:      Jan Ketil Skanke @ CloudWay
        Contact:     @JankeSkanke
        Created:     2020-10-08
        Updated:     2020-10-08
        Version history:
        1.0.0 - (2020-20-09) Initial Version
#>    
param (
    [parameter(Mandatory = $true, HelpMessage = "ClientID of the Azure AD Application is needed")]
    [ValidateNotNullOrEmpty()]
    [string]$clientId,
    [parameter(Mandatory = $true, HelpMessage = "TenantID for the Azure AD Tenant is needed")]
    [ValidateNotNullOrEmpty()]
    [string]$tenantId
)
# Functions defined here
function Write-LogEntry {
	param (
		[parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
		[ValidateNotNullOrEmpty()]
		[string]$Value,
		[parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		[ValidateNotNullOrEmpty()]
		[ValidateSet("1", "2", "3")]
		[string]$Severity,
		[parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
		[ValidateNotNullOrEmpty()]
		[string]$FileName = "Invoke-MFAPopulateSMS.log"
	)
	# Determine log file location
    $LogFileName = "Invoke-MFAPopulateSMS"
    $LogFilePath = "$PSSCriptroot\$FileName"
	
	# Construct time stamp for log entry
	$Time = -join @((Get-Date -Format "HH:mm:ss.fff"), " ", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
	
	# Construct date for log entry
	$Date = (Get-Date -Format "MM-dd-yyyy")
	
	# Construct context for log entry
	$Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
	
	# Construct final log entry
	$LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($LogFileName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
	
	# Add value to log file
	try {
		Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
		if ($Severity -eq 1) {
			Write-Verbose -Message $Value
		} elseif ($Severity -eq 3) {
			Write-Warning -Message $Value
		}
	} catch [System.Exception] {
		Write-Warning -Message "Unable to append log entry to $LogFileName.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
	}
}
    #Variables
#$clientId = "990f6cde-afd9-41db-99ef-20bfa9af615e"
#$tenantId = "e87630f5-66df-47f3-8747-84801dbf1be7"

#Detect if module exists and exit if missing
Try 
    {
        $MyModule = Get-InstalledModule -Name "MSAL.PS" -ErrorAction Stop
        Write-LogEntry "MSAL Module is installed with version $($MyModule.version)" -Severity 1
        Import-Module MSAL.PS    
    }
catch 
    {
        $ErrorMessage = $_.Exception.Message
        Write-LogEntry -Value "Module is missing $ErrorMessage" -Severity 3
        Break
    }
#Authenticate to MS Graph
Try
    {
        $myAccessToken = Get-MsalToken -DeviceCode -ClientId $clientID -TenantId $tenantID -RedirectUri "https://localhost"
        $Header =  @{Authorization = "Bearer $($myAccessToken.AccessToken)"}      
    }
Catch
    {
        $ErrorMessage = $_.Exception.Message
        Write-LogEntry -Value "Connection to Graph failed with $ErrorMessage"
        Break
    }

if ($Header){
#Get all users where mobile number is registered in AAD 
$Uri = 'https://graph.microsoft.com/beta/users'
$QueryResults = @()
# Invoke REST method and fetch data until there are no pages left.
do {
    $RetryIn = "0"
    $ThrottledRun = $false  
    Write-LogEntry -Value "Querying $Uri..." -Severity 1
    try{
        $Results = Invoke-RestMethod -Method Get -Uri $Uri -ContentType "application/json" -Headers $Header -ErrorAction Continue
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        $Myerror = $_.Exception
        if (($Myerror.Response.StatusCode) -eq "429"){
            $ThrottledRun = $true
            $RetryIn = $Myerror.Response.Headers["Retry-After"] 
            Write-LogEntry -Value "Graph queries is being throttled" -Severity 2
            Write-LogEntry -Value "Setting throttle retry to $($RetryIn) seconds" -Severity 1
        }else
        {
            Write-LogEntry -Value "Inital graph query failed with message: $ErrorMessage" -Severity 3
            Exit 1
        }
    } 
    if ($ThrottledRun -eq $false){
        $QueryResults += $Results.value
    }
    $uri = $Results.'@odata.nextlink'
    Start-Sleep -Seconds $RetryIn
} until (!($uri))
# Return the result and filter the result according to our needs
Write-LogEntry -Value "Number of objects returned $($QueryResults.count)" -Severity 1
$Users = $QueryResults | Where-Object { $_.mobilePhone -match '[0-9]' }
    foreach ($User in $Users) {
        #Get api uri
        $Uri = 'https://graph.microsoft.com/beta/users/{0}/authentication/phoneMethods' -f $user.id
        $PhoneMethods = Invoke-RestMethod -Method Get -Uri $Uri -ContentType "application/json" -Headers $Header -ErrorAction Continue
        if ($PhoneMethods.value) {
                    Write-LogEntry -Value "NOCHANGE: $($user.userPrincipalName) already has authenticationPhone registered [$($phonemethods.phoneNumber)]" -Severity 1
        }
        else {
            Write-LogEntry -Value "ADD: Register [$($user.mobilePhone)] for $($user.userPrincipalName)" -Severity 1
            $Payload = @{
                phoneNumber = $user.mobilePhone
                phoneType   = "mobile"
            } | ConvertTo-Json
            Invoke-RestMethod -Method Post -Uri $Uri -Body $Payload -ContentType "application/json" -Headers $Header -ErrorAction Continue
        }
    }
}
else {
    Write-LogEntry -Value "Unable to authenticate to graph" -Severity 3
    Exit 1
}

