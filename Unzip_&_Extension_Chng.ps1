#Script to change all .ear, .war, and .zips to normal folders for Synopsis Detect scans
#--------Variable definitions-------------
$path = "C:\path\to\directory\" 
$full_path = $path+"*" #Star is required for recursion, must append to end of path above
#----------Function Definitions----------
Function Unzip {
[CmdletBinding()]
Param([Parameter(ValueFromPIpeline)]
$fileInfo
)
    #Write-Host("Name:$($fileInfo.FullName)")
    Write-Host("Extracting $($fileInfo.FullName) to $($fileInfo.Directory)")
    Set-Location -Path $fileInfo.Directory #Same thing as cd XXXX.  Had to in order for expanded .zips to go to zip location
    Expand-Archive -Path $fileInfo.FullName #Open the zip and place it's contents
    if(Test-Path $fileInfo.FullName -PathType Leaf)
    {
        Write-Host("Extraction successful.  Removing $($fileInfo.Name)")
        Remove-Item -Path $fileInfo.FullName #Delete the zip
    }
    else
    {
        Write-Host("File was not extracted correctly")
    }
} 

Function convertToZip{
[CmdletBinding()]
Param([Parameter(ValueFromPIpeline)]
$fileInfo
)
Write-Host("Converting: $($fileInfo.Name) to .zip")
Set-Location -Path $fileInfo.Directory
Rename-Item -Path $fileInfo.FullName -NewName $([System.io.path]::ChangeExtension($fileInfo.Name,".zip"))
}

#--------Main--------------
#Placed in a Do While loop so it reruns and dives 
Do {
Get-ChildItem -Path $full_path -Include *.zip,*ear,*war -Recurse | 
%{
    if($_.Extension -eq ".zip")
    {
        $_ | Unzip
    }
    elseif($_.Extension -eq ".ear" -or $_.Extension -eq ".war")
    {
        $_ | convertToZip

    }
}

} while(Get-ChildItem -Path $full_path -Include *zip, *ear, *war -Recurse)





