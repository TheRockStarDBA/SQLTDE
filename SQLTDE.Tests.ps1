Import-Module $PSScriptRoot\SQLTDE.psm1


InModuleScope SQLTDE{

    Describe "Module Imported"{
        It "Exports SQLTDE Fuctions"{
            Get-Command "New-SQLMasterKey" | Should Be $true
            Get-Command "New-SQLServerCertificate" | Should Be $true
            Get-Command "Backup-SQLServerCertificate" | Should Be $true
            Get-Command "Set-SQLDatabaseEncryption" | Should Be $true
        }
    }
    Describe "New-SQLMasterKey" {
        Mock "Invoke-Sqlcmd"{
                "Master Key Created"   
        }
        It "Imports the SQLPS Module if it is not already"{
            New-SQLMAsterKey -SQLInstance localhost -EncryptionPassword (ConvertTo-SecureString "Password" -AsPlainText -Force)
            Get-Module SQLPS | Should Be $true
        }
        It "Creates a key in the master database"{
            New-SQLMasterKey -SQLInstance localhost -EncryptionPassword (ConvertTo-SecureString "Password" -AsPlainText -Force)
            Assert-MockCalled Invoke-Sqlcmd -Exactly 1 -Scope It  
        }
    }
    
    Describe "New-SQLServerCertificate"{
        Mock "Invoke-Sqlcmd"{
            "SQL Cert Created"   
        }
        It "Imports the SQLPS Module if it is not already"{
            New-SQLServerCertificate -SQLInstance localhost -Subject "Server Name"
            Get-Module SQLPS | Should Be $true
        }
        It "Creates a SQL Server Certificate"{
            New-SQLServerCertificate -SQLInstance localhost -Subject "Server Name"
            Assert-MockCalled Invoke-Sqlcmd -Exactly 1 -Scope It  
        }
    }
    
    Describe "Backup-SQLServerCertificate"{
        New-Item C:\localhost_key -ItemType File
        New-Item C:\localhost_cert -ItemType File

        Mock "Invoke-Sqlcmd"{
            "Cert Backed up"   
        }
        It "Imports the SQLPS Module if it is not already"{
            Backup-SQLServerCertificate -SQLInstance localhost -EncryptionPassword (ConvertTo-SecureString "Password" -AsPlainText -Force) -Path TestDrive:\
            Get-Module SQLPS | Should Be $true
        }
        It "Copies the SQL Key to Path defined"{
            Backup-SQLServerCertificate -SQLInstance localhost -EncryptionPassword (ConvertTo-SecureString "Password" -AsPlainText -Force) -Path TestDrive:\
            (((ls TestDrive:\localhost*).Count) -eq 2) | Should Be $true
            del C:\localhost_cert
            del C:\localhost_key
        }
    }
    Describe "Set-SQLDatabaseEncryption"{
        Mock "Invoke-Sqlcmd"{
            "Database Encrypted"   
        }
        It "Imports the SQLPS Module if it is not already"{
            Set-SQLDatabaseEncryption -SQLInstance localhost -Database test
            Get-Module SQLPS | Should Be $true
        }
        It "Turn on SQL database encryption"{
            Set-SQLDatabaseEncryption -SQLInstance localhost -Database test
            Assert-MockCalled Invoke-Sqlcmd -Exactly 2 -Scope It  
        }
    }
}
