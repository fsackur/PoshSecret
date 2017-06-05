#requires -Version 3


#Path to folder where secrets are stored
New-Variable -Name 'POSH_SECRET_PATH' -Value (Join-Path $env:APPDATA PoshSecret) -Option ReadOnly -Scope Script
if (-not (Test-Path $POSH_SECRET_PATH -PathType Container)) {[void](New-Item $POSH_SECRET_PATH -ItemType Directory)}


#A token or password is discarded if it has less than this long before it expires
New-Variable -Name 'MINIMUM_SECONDS_BEFORE_EXPIRY' -Value 60 -Option ReadOnly -Scope Script `
    -Description 'A token or password is discarded if it has less than this long before it expires'



function Save-PoshSecret {
<#
    .Synopsis
    Stores secrets securely and persistently. Secrets can only be retrieved by the user account that stored them.

    .Description
    Secrets are encrypted with the Windows DPAPI (using PS cmdlets) and saved with metadata in XML format in $POSH_SECRET_PATH.

    A combination of Name and Username is guaranteed unique - storing a new secret with an existing combination of name and username will overwrite the previous secret.

    Only the secret is encrypted. All other data is human-readable.

    .Parameter Name
    A name for the credential (mandatory)
                
    .Parameter Username
    Username (optional)

    .Parameter SecurePassword
    The password or secret to store, as a securestring

    .Parameter Password
    The password or secret to store, as a string

    .Parameter Property
    Extra information to be stored along with the secret, as a hashtable

    .Parameter Expiry
    An optional expiry time for the secret. If this is specified at storage time then, if it has elapsed at retrieval time, the secret will be deleted and not returned

    .Example
    Save-PoshSecret -Name "PentagonServer" -Username "Bob" -PlaintextPassword "hunter2"
    Adds a credential
        
    Silently overwrites any existing credential with the same combination of name and username

    .Example
    $Token = Get-SomeStructuredToken
    Save-PoshSecret -Name "CloudAuthAPI" -PlaintextPassword $Token.AuthToken -Property @{Url="https://auth.provider.com/"} -Expiry $Token.Expiry
        
    Stores an API token with a "URL" property which can be accessed on the retrieved object

    .Example
    Save-PoshSecret -Name "CatFactsAPI" -PlaintextPassword "3aa75b5e46b94a5aa77b0c4b172a4eb4" -Property @{Tags=@("Cat", "Facts", "Interesting")} -Expiry (Get-Date).AddHours(5)
    Adds a credential with a secret component but no username. Metadata tags are stored with the credential and can be accessed on the retrieved object. The credential will be deleted after 5 hours.
#>
    [CmdletBinding(DefaultParameterSetName='Plaintext')]
    [OutputType([void])]
    param(
        #The name of the secret or credential to store
        [Parameter(Mandatory=$true, HelpMessage="The name of the secret or credential")]
        [ValidateNotNullOrEmpty()]
        [string]$Name,

        #Optional username to store with the secret or credential
        [string]$Username,

        #Additional metadata to store with the secret or credential
        [System.Collections.IDictionary]$Property,

        #The secret or password to store, as a secure string
        [Parameter(Mandatory=$true, ParameterSetName = 'SecureString')]
        [securestring]$SecurePassword,

        #The secret or password to store, as a plaintext string
        [Parameter(Mandatory=$true, ParameterSetName = 'Plaintext', HelpMessage="The password to store")]
        [Alias('PlaintextPassword')]
        [string]$Password,
        
        #The expiry time of the secret or credential
        [Parameter(Mandatory=$false)]
        [datetime]$Expiry
    )

    $StandardProperties = @{
        Name = $Name;
        Username = $Username;
        SerializedSecurePassword = '';
        SecurePassword = $null;
        ExpiryTime = '';
        StorageTime = (Get-Date -Format s);
        Version = (Get-Module PoshSecret).Version
    }
    if ($Property) {$StandardProperties += $Property}

    $PoshSecret = New-Object psobject -Property $StandardProperties


    if ($Expiry) {
        if ($Expiry -lt (Get-Date)) {Write-Verbose "Expiry time is in the past; discarding"; return $null}
        $PoshSecret.ExpiryTime = $Expiry.ToString("s")
    }
    if ($PSCmdlet.ParameterSetName -eq 'Plaintext') {$Secret = ConvertTo-SecureString $Password -AsPlainText -Force}
    $PoshSecret.SecurePassword = $SecurePassword
    $PoshSecret.SerializedSecurePassword = ConvertFrom-SecureString $Secret

    $Filename = [System.Uri]::EscapeDataString(($Name, $Username) -join [char]31)
    $PoshSecret | Export-Clixml (Join-Path $POSH_SECRET_PATH $Filename) -Depth 8 -Force
}



function Get-PoshSecret {
<#
    .Synopsis
    Retrieves secrets from persistent storage. Secrets can only be retrieved by the user account that stored them.

    .Description
    Secrets are encrypted with the Windows DPAPI (using PS cmdlets) and saved with metadata in XML format in $POSH_SECRET_PATH.

    A combination of Resource and Username is guaranteed unique. Specifying Resource and, optionally, Username will return a single object (or null if no matching object is found). Specifying no parameters will return all stored objects.

    If no matching object is found, will return null.

    If a matching secret was found but it was stored with an expiry time and is now expired, the secret is deleted and the function returns null. A secret is considered expired if the expiry time is less than $MINIMUM_SECONDS_BEFORE_EXPIRY in the future.

    .Parameter Name
    This is what the secret applies to, for example, an API key. It can be used as a display name.

    .Parameter Username
    An optional username field

    .Parameter AsSecureString
    Return the secret as a securestring (default: PSCredential)

    .Parameter AsPlaintext
    Return the secret as a string (default: PSCredential)
#>
    [CmdletBinding(DefaultParameterSetName='NoParameters')]
    [OutputType([psobject[]], ParameterSetName='NoParameters')]
    [OutputType([psobject], ParameterSetName='ReturnPSObject')]
    [OutputType([pscredential], ParameterSetName='ReturnPSCredential')]
    param(
        #The name of the secret or credential to retrieve
        [Parameter(Mandatory=$true, ParameterSetName='ReturnPSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='ReturnPSObject', ValueFromPipelineByPropertyName=$true)]
        [string]$Name,

        #Username, to select between secrets or credentials with the same name
        [Parameter(Mandatory=$false, ParameterSetName='ReturnPSCredential')]
        [Parameter(Mandatory=$false, ParameterSetName='ReturnPSObject', ValueFromPipelineByPropertyName=$true)]
        [string]$Username,

        #Whether to return a PSCredential object (default is to return a PoshSecret object)
        [Parameter(Mandatory=$true, ParameterSetName='ReturnPSCredential')]
        [switch]$AsPSCredential,

        #Whether to decrypt the secret or password (default is not to return secrets in plaintext)
        [Parameter(Mandatory=$false, ParameterSetName='ReturnPSObject')]
        [switch]$AsPlaintext,

        #Minimum remaining validity in seconds for any secret or credential to be returned. Expired secrets are purged. Only affects secrets stored with the -Expiry parameter
        [uint16]$MinimumSecondsBeforeExpiry = $MINIMUM_SECONDS_BEFORE_EXPIRY
    )


    if ($PSCmdlet.ParameterSetName -eq 'NoParameters') {
        $SecretArray = Get-ChildItem $POSH_SECRET_PATH | foreach {
            $Name, $Username = [System.Uri]::UnescapeDataString($_.Name).Split([char]31)
            $PoshSecret = New-Object psobject -Property @{Name = $Name; Username = $Username}
            Add-PoshSecretDefaultMembers -PoshSecret $PoshSecret
            return $PoshSecret
        }
        return $SecretArray
    }


    #Load the secret from disk
    $Filename = [System.Uri]::EscapeDataString(($Name, $Username) -join [char]31)
    try {
        $PoshSecret = Import-Clixml (Join-Path $POSH_SECRET_PATH $Filename)
    } catch [System.IO.FileNotFoundException] {return $null}


    #Handle expiry
    if ($PoshSecret.ExpiryTime -and ($PoshSecret.ExpiryTime -lt (Get-Date).AddSeconds($MinimumSecondsBeforeExpiry).ToString("s"))) {
        Remove-PoshSecret -Name $Name -Username $Username
        return $null
    }


    #Deserialize SecureString property
    $PoshSecret.SecurePassword = ConvertTo-SecureString $PoshSecret.SerializedSecurePassword


    if ($AsPlaintext) {
        $PoshSecret | Add-Member -Name "Password" -MemberType NoteProperty -Value (ConvertTo-Plaintext $PoshSecret.SecurePassword)
    }
    

    if ($PSCmdlet.ParameterSetName -eq 'ReturnPSCredential') {
        return New-Object pscredential ($PoshSecret.Username, $PoshSecret.SecurePassword)
    }


    Add-PoshSecretDefaultMembers -PoshSecret $PoshSecret
    return $PoshSecret
                      
}



function Remove-PoshSecret {
<#
    .Synopsis
    Removes secrets from persistent storage.

    .Description
    Secrets are encrypted with the Windows DPAPI (using PS cmdlets) and saved with metadata in XML format in $POSH_SECRET_PATH. This function deletes that file in the normal way - it does not perform overwrite scrubbing.

    This function will remove secrets from storage.

    .Parameter Name
    This is what the secret applies to; for example, an API key. It can be used as a display name.

    .Parameter Username
    An optional username field. The secret to delete is identified by the combination of name and username, which is guaranteed unique.

#>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        #The name of the secret or credential to remove
        [Parameter(Mandatory=$true)]
        [string]$Name,

        #The username of the secret or credential to remove
        [Parameter(Mandatory=$false)]
        [string]$Username
    )

    $Filename = [System.Uri]::EscapeDataString(($Name, $Username) -join [char]31)

    try {
        Remove-Item (Join-Path $POSH_SECRET_PATH $Filename) -Force
    } catch [System.IO.FileNotFoundException] {return $null}

}



function Add-PoshSecretDefaultMembers {
<#
    .Synopsis
    Applies formatting info to the PoshSecret object after loading from disk

    .Notes
    Pass-by-reference - the original object is updated

    Do not export
#>
    param($PoshSecret)

    $PoshSecret.PSTypeNames.Insert(0, 'Rax.WindowsAutomation.PoshSecret')
    Add-Member -InputObject $PoshSecret MemberSet PSStandardMembers $(
        $Display = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]('Name', 'Username', 'SecurePassword', 'Password'));
        $Sort =    New-Object System.Management.Automation.PSPropertySet('DefaultKeyPropertySet', [string[]]('Name', 'Username'));
        [System.Management.Automation.PSMemberInfo[]]@($Display, $Sort)
    ) -Force
}



function ConvertTo-Plaintext {
<#
    .SYNOPSIS
    Converts a SecureString to a plaintext string

    .DESCRIPTION
    Converts a SecureString to a plaintext string
        
    .PARAMETER SecureString
    The SecureString to convert to plaintext

    .EXAMPLE
    $Password = ConvertTo-SecureString "hunter2" -AsPlainText -Force
    ConvertTo-Plaintext -SecureString $Password

    Returns the plaintext string from a SecureString
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, Position=0)]
        [Alias("SecurePassword")]
        [System.Security.SecureString]$SecureString
    )

    try {
        $UnsecurePointer = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        $UnsecureString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($UnsecurePointer)
    } finally {
        #This is important, it zeroes out the memory
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($UnsecurePointer)
    }

    return $UnsecureString
}
