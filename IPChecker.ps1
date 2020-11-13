$Excel = New-Object -ComObject Excel.Application
$Workbook = $Excel.Workbooks.Open('XXXXXXXXXXX')

$Worksheet = $Workbook.Worksheets.Item(1)

#Get all rows in excel sheet
$NumRows = ($worksheet.UsedRange.Rows).count

#Declare starting positions for each row
$rowIp, $colIp = 1,1
$rowHostname, $colHostname = 1,2
$rowPort, $colPort = 1,3

$count = 1
for($i = 1; $i -le $NumRows-1; $i++)
{

$IP = $Worksheet.Cells.Item($rowIp + $i, $colIp).text
$Hostname = $Worksheet.Cells.Item($rowHostname + $i, $colHostname).text
$Port = $Worksheet.Cells.Item($rowPort + $i, $colPort).text

    if($Hostname)
    {
        if(!$Port)
        {
        #Append IP to text file
            Add-Content C:\path\to\dump\test.txt "$IP"
        }
    }
}

Write-Output " "
Write-Host($count)



#Must quit at the end or else the excel will be locked
$Excel.Quit()