#--------Global Variables-------------------- 

$reportFileName = "XXXXXXX.csv" 

$report = @() 

$total_subnets = @() 

$total_NICs = @() 

$nsgs = Get-AzNetworkSecurityGroup 

#--------------------- 

  

#--------Main---------- 

foreach($nsg in $nsgs) 
{ 
    #--------Local Variables------------ 
    $subnetsInNSG = $nsg.SubnetsText 

    $NICSInNSG = $nsg.NetworkInterfacesText 
    #-----------------------------------   
    #Gather subnet and NIC data first.  Code is the same for both.  Will look to generalize into function later. 

    if($subnetsInNSG -ne $null) 
    {   
        #The nsg.SubnetsText comes in JSON form.  Convert it to an array so I can change it for csv output 
        $subnetJSON = ConvertFrom-Json –InputObject $subnetsInNSG 

        <#When pulling from Azure, the subnet/nic data is in a key, value pair
        #ID Value == Data we want

        foreach($subnet in $subnetJSON.Id) 

        {   #slice up string slash delimited to remove them from output 
            $subnet = $subnet.Split("/") 
            #subnet[8] = the VNET.  Here i'm adding the subnet name along with the VNET it's in between ( ) 
            $subnet_to_add = $subnet[$subnet.Length - 1] + "(" + $subnet[8] + ")" 
            #The last piece in the string is the name of the data we want, so add only that to array 
            $total_subnets+=$subnet_to_add 
       } 
       #Join all elements again, separated by comma so it's easy to read/sort through for any potential analysis 
       $total_subnets = $total_subnets -join ',' 
    } 

     

    if($NICSInNSG -ne $null) 
    { 
        $NICJSON = ConvertFrom-Json –InputObject $NICSInNSG 
 
        foreach($nic in $NICJSON.Id) 
        {               
            $nic = $nic.Split("/") 
            $nic_data = Get-AzNetworkInterface -Name $nic[$nic.Length - 1] | Select-Object -Property IpConfigurationsText        
            $nic_data = ConvertFrom-Json -InputObject $nic_data.IpConfigurationsText

            foreach($temp_nic in $nic_data.Subnet.Id)
            {
               #Pull in same manner as above, except we're adding VNETs to csv as well.
               #$temp_nic[$temp_nic.Length - 3] = VNET
               #$temp_nic[$temp_nic.Length - 1] = SUBNET
               $temp_nic = $temp_nic.split("/")           
               $nic_to_add = $nic[$nic.Length - 1] + "(" + $temp_nic[$temp_nic.Length - 3] + "\" + $temp_nic[$temp_nic.Length - 1] + ")"
               $total_NICs+=$nic_to_add
            }
       } 
       $total_NICs = $total_NICs -join ',' 
    } 

    #Pull default rules using the config call.Add NSG name, subnet and NICs for organization and append to the overall report 

    $def_rules = Get-AzNetworkSecurityRuleConfig -DefaultRules -NetworkSecurityGroup $nsg | Select-Object -Property @{n="NSG Name";e={$nsg.Name}},@{n="Rule Name";e={$_.Name}},@{n="Subnets";e={$total_subnets}}, @{n="NICs";e={$total_NICs}}, Direction, Priority,
    @{n="SourcePortRange";e={$_.SourcePortRange}}, 
    @{n="DestinationPortRange";e={$_.DestinationPortRange}}, 
    @{n="SourceAddressPrefix";e={$_.SourceAddressPrefix}}, 
    @{n="DestinationAddressPrefix";e={$_.DestinationAddressPrefix}},
    Protocol,Access,Description 

    $report+=$def_rules 

    #same as above but for user created rules.   

    $sec_rules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg | Select-Object -Property @{n="NSG Name";e={$nsg.Name}},@{n="Rule Name";e={$_.Name}},@{n="Subnets";e={$total_subnets}}, @{n="NICs";e={$total_NICs}}, Direction, Priority,
    @{n="SourcePortRange";e={$_.SourcePortRange}}, 
    @{n="DestinationPortRange";e={$_.DestinationPortRange}}, 
    @{n="SourceAddressPrefix";e={$_.SourceAddressPrefix}}, 
    @{n="DestinationAddressPrefix";e={$_.DestinationAddressPrefix}},
    Protocol,Access,Description 

    $report+=$sec_rules 

    Write-Host("NSG: $($nsg.Name)") 

    #Empty subnet/nic arrays 

    $total_subnets = @() 
    $total_NICs = @() 
} 

$report | Export-CSV "~\$($reportFileName)"-NoTypeInformation 