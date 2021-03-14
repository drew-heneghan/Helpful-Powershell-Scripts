clear
#-------------Function Definitions-----------------------
function Check-Identifier
{
    param(
    [string]$CurrentIdentifier,
    [PSCustomObject[]]$IdentifierList
    )
    #if identifier contains it, return true, else false
    if($IdentifierList.Contains($CurrentIdentifier))
    {
        return $true
    }
    else
    {
        return $false
    }
}
function Format-Vuln
{
#This function formats the vulnerability data per our template of VULN ID: Description. Fix data

    param(
    [PSCustomObject[]]$List
    )
    #Local Variables to pull relevant data to be formatted
    $Identifier
    $Description
    $fix
    $retVal

    forEach($property in $List)
    {
     $Identifier = $property.'Vulnerability Id'
     $Description = $property.'Description'
     $fix = $property.'Fix List'
    }

    $retVal = "$($Identifier): $($Description). Fixed in $($fix)"
    return $retVal
}
function Format-Filepath 
{
    #This function loops through all filepaths for a component and returns an appended string with everything
    param(
    [PSCustomObject[]]$filepath_string
    )

    $all_file_locations = @();

    for($i = 0; $i -lt $total_locations.Length; $i++)
    {
        $temp_context = $total_locations[$i] | Select-Object -ExpandProperty 'Archive context'
        $temp_path = $total_locations[$i] | Select-Object -ExpandProperty 'Path'
        $temp_full_path = $temp_context + $temp_path

        $temp_full_path.Replace('//', '/')

        if($temp_full_path.Substring(0,1) -eq "0")
        {
            $temp_full_path = $temp_full_path.TrimStart("0")
        }

    $all_file_locations+= $temp_full_path + "`n"
    }

    return $all_file_locations

}
function Compile-Report
{
    param(
    [PSCustomObject[]]$vuln_data,
    [PSCustomObject[]]$file_path,
    [string]$toolName
    )
    #Info for the Workitem title and description that is pulled from the data.csv file
    $Component_Name = $vuln_data[0] | Select-Object -ExpandProperty 'Component Name'
    $Component_Version = $vuln_data[0] | Select-Object -ExpandProperty 'Component version name' 
    $num_criticals = $vuln_data[0] | Select-Object -ExpandProperty 'Critical Vulnerabilities'
    $num_highs = $vuln_data[0] | Select-Object -ExpandProperty 'High Vulnerabilities'
    $num_mediums = $vuln_data[0] | Select-Object -ExpandProperty 'Medium Vulnerabilities'
    $num_lows = $vuln_data[0] | Select-Object -ExpandProperty 'Low Vulnerabilities'
    $fix_version = $vuln_data[0] | Select-Object -ExpandProperty 'Fix List'

    #These lists represent the different vuln sections that will be in the work item descriptoin
    $CriticalInfo = @();
    $HighInfo = @();
    $MediumInfo = @();
    $LowInfo = @();

    #Entire report for single component.  This is what is outputted to the .txt files later on
    $vuln_report = @();

    #Loop through all filepaths where the single component is located and append to this string to be added to the description
    $total_locations = ""

    #Created Filename string for the title
    $fileName = "$($Component_Name)$($Component_Version)"
    
    for($i = 0; $i -lt $file_path.Length; $i++)
    {
        $tempArchive = $file_path[$i] | Select-Object -ExpandProperty 'Archive context'
        $tempPath = $file_path[$i] | Select-Object -ExpandProperty 'Path'
        $total_locations+= $tempArchive + $tempPath + "`r"
    }
    #Remove non alphanumeric characters so filename is valid
    $pattern = '[^a-zA-Z0-9.]'
    $fileName = $fileName -replace $pattern,''
  
    #Put together strings 
    $WorkItem_Title = "[$($toolName)] Vulnerability in $($Component_Name) $($Component_Version)"
    $WorkItem_Description = "`nThere are vulnerabilities associated with this component($($num_criticals) Critical, $($num_highs) High, $($num_mediums) Medium, $($num_lows) Low)`nAll recommended fixes are as of $($computer_date)`n`nFilepath: $($total_locations)`n`nFind the details below"
    
    #Check all vuln counts and add Section headers if applicable
    if($num_criticals -ne 0)
    {
        $CriticalInfo+="`nCritical"
    }
    if($num_highs -ne 0)
    {
        $HighInfo+="`nHigh"
    }
    if($num_mediums -ne 0)
    {
        $MediumInfo+="`nMedium"
    }
    if($num_lows -ne 0)
    {
        $LowInfo+="`nLow"
    }
    #Loop through all vulns for the specific component and format it as VULN ID: Description. Version Fix
    ForEach($vuln in $vuln_data)
    {
        $temp = @()
        if($vuln.'Security Risk' -eq 'Critical')
        {
            $temp = Format-Vuln -List $vuln
            $criticalInfo+=$temp
        }
        elseif($vuln.'Security Risk' -eq 'High')
        {
            $temp = Format-Vuln -List $vuln
            $highInfo+=$temp

        }
        elseif($vuln.'Security Risk' -eq 'Medium')
        {
            $temp = Format-Vuln -List $vuln
            $mediumInfo+=$temp
        }    
        elseif($vuln.'Security Risk' -eq 'Low')
        {
            $temp = Format-Vuln -List $vuln
            $lowInfo+=$temp
        }
    }
    #Append everything
    $vuln_report+=$WorkItem_Title
    $vuln_report+=$WorkItem_Description
    $vuln_report+=$criticalInfo
    $vuln_report+=$highInfo
    $vuln_report+=$mediumInfo
    $vuln_report+=$lowInfo

    #Export and print out an error if it doesn't work
    try{
    $vuln_report | Out-File C:\bd\WorkItem_$($fileName).txt
    }
    catch{Write-Host -ForegroundColor Red -BackgroundColor Black "Error while exporting file: $($fileName)"}
}

#-----------------------Variables------------------------
#Get date from computer
$computer_date = Get-Date -Format "MM/dd/yyy"
#Import data from spreadsheets
$data = Import-Csv -Path XXXXXXXXXXX
$filepath_data = Import-Csv -Path XXXXXXXXXXXXX
#Name of scanning tool
$tool_name = "SCANNER NAME"
#The data being read in contains repeated vulnerability identifiers.  Meaning, component X will show CWE-2020 multiple times.
$identifiers = @();
#Parsed data will contain the accuracte list of vulnerabilties used to be entered into DevOps
$parsed_data = @();
#------------------------Main----------------------------
#This loop removes the duplicate vulnerabiltiies per component
for($i = 0; $i -lt $data.Length; $i++)
{
    $sum_of_vulns = [int]$data[$i].'Critical Vulnerabilities' + [int]$data[$i].'High Vulnerabilities' + [int]$data[$i].'Medium Vulnerabilities' + [int]$data[$i].'Low Vulnerabilities'

    if($sum_of_vulns -le 0)
    {#If there are no vulns...then skip.  It was either do it this way or filter the "Patched" column in the CSV, and I did not want to mess with the Macro again
        continue
    }
    #Doing it by Version ID to ensure same components with different versions used in the same project are still covered
    if($data[$i].'Version id' -eq $data[$i+1].'Version id')
    {   
        #Check if CWE XXXX has already been recorded
        if(Check-Identifier -CurrentIdentifier $data[$i].'Vulnerability id' -IdentifierList $identifiers)
        {
           #then go to the next vuln for that component since this is a duplicate value
           continue
        }
        else
        {#Else...data is unique and both the Vuln ID and entire component are accounted for
           $identifiers+=$data[$i].'Vulnerability id'
           $parsed_data+=$data[$i]
        }
    }
    else
    {   #This check is to see whether the final vuln for that component is acccounted for or not.
        if(!(Check-Identifier -CurrentIdentifier $data[$i].'Vulnerability id' -IdentifierList $identifiers))
        {
           $parsed_data+=$data[$i]
        }
           #reset the identifiers for the next component
           $identifiers = @();
    }
}
$tempArr_data = @();
$tempArr_source = @();

for($i = 0; $i -lt $parsed_data.Length; $i++)
{
    if($parsed_data[$i].'Version id' -eq $parsed_data[$i+1].'Version id')
    {
        $tempArr_data +=$parsed_data[$i]
        #Skip to next vulnerability within same component
        continue
    }
    else
    {   #add the last element of that component before generating the report
        $tempArr_data+=$parsed_data[$i]

        for($j = 0; $j -lt $filepath_data.Length; $j++)
        {
             if($filepath_data[$j].'Version id' -eq $parsed_data[$i].'Version id')
             {
                $tempArr_source+=$filepath_data[$j]
                continue
             }
        }
        #format to text
        Compile-Report -vuln_data $tempArr_data -file_path $tempArr_source -toolNamne $tool_name
        #empty arrays for next component
        $tempArr_source= @();
        $tempArr_data = @();
    }
}

