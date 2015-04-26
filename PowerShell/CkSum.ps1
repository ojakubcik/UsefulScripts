# Checksum generation/checking tool
# Ondrej Jakubcik, 2015
# 
# This script is in public domain.
Param (
    [Switch] $Md5,
    [Switch] $Sha1,
    [Switch] $Sha256,
    [Switch] $Sha512,
    [Switch] $Check,
    [String[]] $Arguments
)

[String] $algo = $null
$runCheck = $false
if ($Md5  -And !$Sha1 -And !$Sha256 -And !$Sha512 -And !$Check) { $algo = "MD5" }
if (!$Md5 -And  $Sha1 -And !$Sha256 -And !$Sha512 -And !$Check) { $algo = "SHA1" }
if (!$Md5 -And !$Sha1 -And  $Sha256 -And !$Sha512 -And !$Check) { $algo = "SHA256" }
if (!$Md5 -And !$Sha1 -And !$Sha256 -And  $Sha512 -And !$Check) { $algo = "SHA512" }
if (!$Md5 -And !$Sha1 -And !$Sha256 -And !$Sha512 -And  $Check) { $runCheck = $true }

If (!$algo -And !$runCheck) {
    Write-Error 'Invalid combination of arguments passed.'
    Exit 1
}

function Proc-Args {
    [CmdletBinding()]
    Param (
        # [ValidateScript({$_.Count > 0})]
        [String[]] $fileNames
    )
    $files = Get-ChildItem $fileNames

    [String[]] $result = @()
    Foreach ($file in $files) {
        $include = $true
        Try {
            $stream = $file.Open([System.IO.FileMode]"Open",[System.IO.FileAccess]"ReadWrite",[System.IO.FileShare]"None")
            $stream.Dispose()
        } Catch [System.IO.IOException] {
            $include = $false
        }

        If ($include -And (Get-Item $file).Length -eq 0) {
            $include = $false
            Write-Warning "Skipping $file, it has zero length."
        }

        If ($include) { $result += $file.Name }
    }

    Return $result
}

function Checksum-Files {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String[]] $files,
        [Parameter(Mandatory=$true)]
        [ValidateSet("MD5", "SHA1", "SHA256", "SHA512")]
        [String] $algo
    )
    Try {
        Foreach ($file in $files) {
            $cksum = Checksum-File $file $algo
            Write-Host "$cksum  $file"
        }
    }
    Catch {
        $msg = $_.Exception.Message
        Write-Error "Unknown error: $msg" 
        Return 1
    }
    Return 0
}

function Do-Check {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String] $hashfile
    )
    $hashes = Read-Checksums $hashfile
    $failures = 0
    $nonexistent = 0
    $success = 0

    Foreach ($hash in $hashes)
    {
        $fn = $hash.FileName
        If (Test-Path $hash.FileName) {
            $computed = Checksum-File $fn $hash.Algorithm
            If ($computed -eq $hash.Hash) {
                $success += 1
                Write-Host "${fn}: OK"
            }
            Else {
                $failures += 1
                Write-Error "${fn}: FAILED"
            }
        } 
        Else {
            Write-Warning "File '$fn' doesn't exist, skipping."
            $nonexistent += 1
        }
    }
    Write-Host "COMPLETE: $success OK, $failures FAILED, $nonexistent NOT FOUND"
    If ($success -eq 0 -Or $failures -ne 0) {
        Return 1
    }

    If ($nonexistent -ne 0 -And $success -eq 0 -And $failures -eq 0) {
        Write-Error "None of the passed files were found, are you in correct directory?"
        Return 1
    }

    Return 0
}

function Checksum-File {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_})]
        [String] $fileName,

        [Parameter(Mandatory=$true)]
        [ValidateSet("MD2", "MD4", "MD5", "SHA1", "SHA256", "SHA384", "SHA512")]
        [String] $algo
    )

    [String[]] $retvals = CertUtil -hashfile $fileName $algo
    If ($LastExitCode -ne 0) { Throw 'Error when executing CertUtil.' }
    [String] $retval = $retvals[1] -replace '\s',''
    Return $retval
}

Add-Type @"
using System;
public struct HashDetails {
    public String FileName;
    public String Hash;
    public String Algorithm;
}
"@


function Read-Checksums {
    [CmdletBinding()]
    Param (
        [ValidateScript({Test-Path $_})]
        [String] $fileName
    )

    $hashes = Get-Content $fileName
    $result_array = @();
    Foreach ($line in $hashes) {
        # Fix line endings
        $line = $line -replace '\r\n','\n'
        $line = $line -replace '\r','\n'
        $line = $line -replace '\n','\r\n'
        Try {
            $parsed = Parse-Checksum-Line $line
        }
        Catch {
            Write-Warning "Cannot parse: '$line'"
        }
        $result_array += $parsed
    }
    Return $result_array
}


function Parse-Checksum-Line {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $line
    )

    # There are two formats:
    # abcdefe....12ad filename.ext
    # SHA123(filename.ext) = abcdefe....12ad
    $correct = $line -match '^([A-Fa-f0-9]+)\s+\*?(.*)'
    If ($correct) {
        [String] $algo = ""
        Switch ($Matches[1].Length) {
            32  { $algo = "MD5" }
            40  { $algo = "SHA1" }
            64  { $algo = "SHA256" }
            96  { $algo = "SHA384" }
            128 { $algo = "SHA512" }
            default { $algo = "UNKNOWN" }
        }
        $result = New-Object HashDetails -Property @{
            FileName = $Matches[2]
            Hash = $Matches[1].ToLower()
            Algorithm = $algo
        }
        Return $result
    } Else {
        $correct = $line -match '^([Mm][Dd](2|4|5)|[Ss][Hh][Aa](1|256|384|512))\s*\((.*)\)\s+=\s+([A-Fa-f0-9]+)'
        If (!$correct) { Throw 'Invalid hash format' }
        $result = New-Object HashDetails -Property @{
            FileName = $Matches[4]
            Hash = $Matches[5].ToLower()
            Algorithm = $Matches[1].ToUpper()
        }
        Return $result
    }
}

If ($runCheck) {
    If ($Arguments.Count -ne 1) {
        Write-Error "For checking, only one argument can be specified."
        Exit 1
    }

    $result = Do-Check $Arguments[0]
}
Else {
    If ($Arguments.Count -eq 0) {
        Write-Error "For checksumming, at least one argument must be specified."
        Exit 1
    }

    $files = Proc-Args $Arguments
    $result = Checksum-Files $files $algo
}

Exit $result
