# Helpful-Powershell-Scripts
Powershell scripts that allow me to focus more on the things I enjoy 

<h3>Convert n Extract</h3>
<p> Searches for any file extensions that you specify and, upon finding one, will extract the contents within the directory recursively into a folder with the same name.  I use this a lot for vetting source code in order to ensure file traversing is possible with OSS scanners.</p>
  
<h3> NSG Export</h3>
<p> Exports all Network Security Groups from an Azure subscription and displays the below information:</p>
    <table>
      <tr>Network Security Group Name</tr>
  <tr>Network Security Group Name</tr>
  <tr>Network Security Group Rule Name</tr>
  tr>Subnet(VNET)</tr>
  <tr>Network Interfaces(VNET/Subnet)</tr>
  <tr>Rule Direction</tr>
  <tr>Rule Priority</tr>
  <tr>Rule Source Port Range</tr>
  <tr>Rule Destination Port Range</tr>
  <tr>Rule Direction</tr>
  <tr>Rule Source Addresss Range</tr>
  <tr>Rule Destination Address Range</tr>
  <tr>Rule Protocol</tr>
  <tr>Rule Action</tr>
  <tr>Rule Description</tr>
  
  <p><b>Note:</b>In order for this script to execute properly, you must use Azure Powershell and authenticate to your portal using Connect-AzAccount.  After you're authorized, execute <b>Get-AzContext -ListAvailable</b> followed by <b>Select-AzContext -Name ""</b> in order to select a subscription to pull all NSGs from.  
