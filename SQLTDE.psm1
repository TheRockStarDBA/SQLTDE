function New-SQLMasterKey
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        $SQLInstance,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
		[securestring]
        $EncryptionPassword = (Read-Host -AsSecureString -Prompt "Input password for encrypting the Master Key")
	)
        Begin
        {
			Import-SQLModule
			$masterDB = "master" 
        }

        Process
        {
			$MASTER_KEY_QUERY = "CREATE MASTER KEY ENCRYPTION BY PASSWORD = '{0}';" -f (Show-Password -EncryptedPassword $EncryptionPassword)
			try
			{
				Invoke-Sqlcmd -query $MASTER_KEY_QUERY -ServerInstance $SQLInstance -Database $masterDB
				Write-Verbose "Created Master Key for instance $SQLInstance"
			}
			catch [System.Exception]
			{
				Write-Error "Error creating Master Key"
			}
			finally
			{
				
			}
			
        }

        End
        {
			$EncryptionPassword = $null
        }
}

function New-SQLServerCertificate
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        $SQLInstance,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=1)]
        $Subject
	)
        Begin
        {
			Import-SQLModule
			$masterDB = "master" 
			$splitName = ($SQLInstance -split "\\")
			$splitname = $splitname[$splitName.Count-1] -replace "-",""
			
        }

        Process
        {
			try
			{
				$SQL_SERVER_CERT_QUERY = "CREATE CERTIFICATE {0}_Cert WITH SUBJECT = '{1}'" -f $splitname,$Subject
				Invoke-Sqlcmd -query $SQL_SERVER_CERT_QUERY -ServerInstance $SQLInstance -Database $masterDB 
				Write-Verbose "Certificate Created Successfully"
			}
			catch [System.Exception]
			{
				Write-Error "Failed to create certificate"
			}
			finally
			{

			}

        }

        End
        {

        }
}

function Backup-SQLServerCertificate
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        $SQLInstance,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=1)]
		[securestring]
        $EncryptionPassword = (Read-Host -AsSecureString -Prompt "Input password for encrypting the Master Key"),
		[Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true,Position=2)]
        $Path
	)
        Begin
        {
			Import-SQLModule
			$masterDB = "master" 
			$SQLServer = new-object ('Microsoft.SqlServer.Management.Smo.Server') $SQLInstance
			$source = $null
			if($SQLServer.DefaultFile -eq $null){
				$source = $SQLServer.MasterDBPath
			}
			else{
				$source = $SQLServer.DefaultFile
			}
			$splitName = ($SQLInstance -split "\\")
			$splitname = $splitname[$splitName.Count-1] -replace "-",""
        }

        Process
        {

			$SQL_SERVER_CERT_BACKUP_QUERY = "BACKUP CERTIFICATE {0}_Cert TO FILE = '{0}_Cert' WITH PRIVATE KEY (FILE = '{0}_Key', ENCRYPTION BY PASSWORD = '{1}')" -f $splitname,(Show-Password -EncryptedPassword $EncryptionPassword)
			Invoke-Sqlcmd -query $SQL_SERVER_CERT_BACKUP_QUERY -ServerInstance $SQLInstance -Database $masterDB
			if($Path -eq $null){
				Write-Verbose "Files saved to Default SQL Data Directory, no further backups made"
			}
			else{
				Copy "$source\$($splitname)_Cert" $Path
				Copy "$source\$($splitname)_Key" $Path
			}
        }

        End
        {
			$EncryptionPassword= $null
        }
}

function Set-SQLDatabaseEncryption
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        $SQLInstance,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=1)]
        $Database
	)
        Begin
        {
			Import-SQLModule
			$splitName = ($SQLInstance -split "\\")
			$splitname = $splitname[$splitName.Count-1] -replace "-",""
			
        }

        Process
        {
			try
			{
				$SQL_DB_KEY_QUERY = "CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_128 ENCRYPTION BY SERVER CERTIFICATE {0}_Cert" -f $splitname
				Invoke-Sqlcmd -query $SQL_DB_Key_QUERY -ServerInstance $SQLInstance -Database $Database 
				Write-Verbose "Database Key Created Successfully"
			}
			catch [System.Exception]
			{
				Write-Error "Failed to create certificate"
			}
			finally
			{

			}
			
			try {
				$SQL_DB_ENCRYPT_QUERY = "ALTER DATABASE {0} SET ENCRYPTION ON" -f $Database
				Invoke-Sqlcmd -query $SQL_DB_ENCRYPT_QUERY -ServerInstance $SQLInstance -Database $Database 
				Write-Verbose "Database Encrypted Successfully"
				
			}
			catch [System.Exception] {
				Write-Error "Failed to encrypt database"
			}
			finally {
				
			}

        }

        End
        {

        }
}

function Remove-SQLDatabaseEncryption
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        $SQLInstance,
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=1)]
        $Database,
		[Switch]$RemoveKey = $false
	)
        Begin
        {
			Import-SQLModule
			$splitName = ($SQLInstance -split "\\")
			$splitname = $splitname[$splitName.Count-1] -replace "-",""
			
        }

        Process
        {
			
			try {
				$SQL_DB_ENCRYPT_QUERY = "ALTER DATABASE {0} SET ENCRYPTION OFF" -f $Database
				Invoke-Sqlcmd -query $SQL_DB_ENCRYPT_QUERY -ServerInstance $SQLInstance -Database $Database 
				Write-Verbose "Removed Database Encryption Successfully"
				
			}
			catch [System.Exception] {
				Write-Error "Failed to remove database encryption"
			}
			finally {
				
			}
			if($RemoveKey){
				try
				{
					$i = 0
					do {
						$i++
						if($i -gt 10){
							Write-Error "Could not determine if encryption has been disabled. Key has not been removed."
						}
						$DB = Get-SQLUserDBs -SQLInstance $SQLInstance | Where-Object{$_.Database -eq $Database}
					} until ($DB.Encrypted -eq $false)
					$SQL_DB_KEY_QUERY = "DROP DATABASE ENCRYPTION KEY"
					Invoke-Sqlcmd -query $SQL_DB_Key_QUERY -ServerInstance $SQLInstance -Database $Database 
					Write-Verbose "Database Key Removed Successfully"
				}
				catch [System.Exception]
				{
					Write-Error "Failed to remove database encryption key"
				}
				finally
				{

				}
			
			}
        }

        End
        {

        }
				
}

function Show-Password
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        [securestring]
		$EncryptedPassword
	)
        Begin
        {
			     
        }

        Process
        {
			$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptedPassword)
			$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        }

        End
        {
			return $PlainPassword
        }
}

function Import-SQLModule
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
	)
        Begin
        {
			     
        }

        Process
        {
			if (-not(Get-Module -name 'SQLPS')) 
			{
				if (Get-Module -ListAvailable | Where-Object {$_.Name -eq 'SQLPS' }) {
					Push-Location 
                    Import-Module -Name 'SQLPS' -DisableNameChecking | Out-Null
					Pop-Location 
				}
				else{
					Write-Error " Could not find SQL Powershell module. Check it is installed and try again"
				}
            }
        }

        End
        {
        }
}

function Get-SQLUserDBs{
	[CmdletBinding()]
    [OutputType([int])]
    param
    (
		[Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true,Position=0)]
        $SQLInstance
	)
	Begin
	{
		$Database = "master"
		$returnvalues = @()
	}
	Process
	{
		
		try
		{
			$SQL_ALL_DB_QUERY = "SELECT name, is_encrypted FROM sys.databases WHERE name NOT IN('model','master','msdb','tempdb')"
			$Dbs = Invoke-Sqlcmd -query $SQL_ALL_DB_QUERY -ServerInstance $SQLInstance -Database $Database 
			Write-Verbose "Querying for all user DBs"
		}
		catch [System.Exception]
		{
			Write-Error "Failed to enumerate databases"
		}
		finally
		{
			
		}
		
		foreach($DB in $Dbs){
			$returnvalues += [PSCustomObject]@{
				Database = $DB.name
				Encrypted = $DB.is_encrypted
				SQLInstance = $SQLInstance
			}
		}
		$returnvalues		
						
	}

	End
	{
		
	}
	
}
