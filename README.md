# Helpful-Powershell-Scripts
Powershell scripts that allow me to focus more on the things I enjoy 

<h3>Convert n Extract</h3>
<p> Searches for any file extensions that you specify and, upon finding one, will extract the contents within the directory recursively into a folder with the same name.  I use this a lot for vetting source code in order to ensure file traversing is possible with OSS scanners.</p>
  
<h3> NSG Export</h3>
<p> Exports all Network Security Groups from an Azure subscription and displays the below information:</p>
<table>
  <tr>
    <td>Network Security Group Name</td>
  </tr>
  <tr>
    <td>Network Security Group Name</td>
  </tr>
  <tr>
    <td>Network Security Group Rule Name</td>
  </tr>
  <tr>
  <td>Subnet(VNET)</td>
  </tr>
  <tr>
  <td>Network Interfaces(VNET/Subnet)</td>
</tr>
  <tr>
    <td>Rule Direction</td>
  </tr>
  <tr>
    <td>Rule Priority</td>
  </tr>
  <tr>
    <td>Rule Source Port Range</td>
  </tr>
  <tr>
    <td>Rule Destination Port Range</td>
  </tr>
  <tr>
    <td>Rule Direction</td>
  </tr>
  <tr>
    <td>Rule Source Addresss Range</td>
  </tr>
  <tr>
    <td>Rule Destination Address Range</td>
  </tr>
  <tr>
    <td>Rule Protocol</td>
  </tr>
  <tr>
    <td>Rule Action</td>
  </tr>
  <tr>
    <td>Rule Description</td>
  </tr>
</table>
  
  <p><b>Note:</b> In order for this script to execute properly, you must use Azure Powershell and authenticate to your portal using Connect-AzAccount.  After you're authorized, execute <b>Get-AzContext -ListAvailable</b> followed by <b>Select-AzContext -Name ""</b> in order to select a subscription to pull all NSGs from.  
