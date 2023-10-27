#V3

#################################################################################
#DISCLAIMER: This is not an official PowerShell Script. We designed it specifically for the situation you have encountered right now.#Please do not modify or change any preset parameters. 
#Please note that we will not be able to support the script if it is changed or altered in any way or used in a different situation for other means.
#This code sample is provided "AS IT IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#This sample is not supported under any Microsoft standard support program or service.. 
#Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. #The entire risk arising out of the use or performance of the sample and documentation remains with you. 
#In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, 
#or other pecuniary loss) arising out of  the use of or inability to use the sample or documentation, even if Microsoft has been advised of the possibility of such damages.
#################################################################################

# This script requires app registration with the following API permissions:

# Application - windowsdefenderATP - Vulnerability.read
#                                  - Machines.Read.All
#################################################################################

Clear-Host

#request path to save csv file
$path_ = Read-Host "Full file path for csv output (Filename included without extension) "


#log keep for CSV build
$Logs = @()
$machineLogs = @()

#initialize Progress bars
$pbCounter = 0

if(!([string]::IsNullOrEmpty($path_) )) {
    #if $path is not null or empty

    try {
        
        #setting vars for test
        $grantType = "client_credentials" #connection flow
        $clientId = Read-host "App Id "  #id 
        $clientSecret = Read-host "App Secret "  #secret 
        $tenantId = Read-host  "Tenant Id " #tenant
        
        $oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token" 
        $resourceAppIdUri = 'https://api.securitycenter.microsoft.com/'

        #*****************vulnerabilities******************************************

        $authBody =@{
            grant_type = $grantType
            client_id = $clientId
            client_secret = $clientSecret 
            resource = $resourceAppIdUri
        }

        #get access token
        $token = Invoke-RestMethod -Method POST -Uri $oAuthUri -Body $authBody -ContentType "application/x-www-form-urlencoded"

        #setting headers for the request
        $headers = @{
            "Content-Type" = "application/json"
            Accept = "application/json"
            Authorization = "Bearer $($token.access_token)"
        }

        Write-Host "Aquiring Machine info..." -ForegroundColor Yellow
        
        #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        #region machineInfo
        #get machine information URL
        $machineUrI = "https://api.securitycenter.microsoft.com/api/machines/"

        #Machine info Request
        $response = Invoke-WebRequest -Method GET -Uri $machineUrI -Headers $headers 

        #handle paging
        while($true){

            #clear tags var
            [string]$machineTags_ = ""

            #get json reply to check if @odata.nexlink exists in current API call result 
             $workableJason = $response.Content | ConvertFrom-json
            
            #cycle in each page
            foreach($machineobj in $($workableJason.value)){             

                foreach ($machinetagValue in $($machineobj.machineTags)){

                    $machineTags_ +=  $machinetagValue + " "
    
                }

                $allMachines = New-Object PSObject -Property @{                    
                    "ComputerDnsName" = $machineobj.ComputerDnsName
                    "Tags" = $machineTags_
                    "Id" = $machineobj.Id
                }

                ##clear tags var in foreach cycle
                [string]$machineTags_ = ""

                $machineLogs += $allMachines
            }

        
            if($workableJason.'@odata.nextlink') {
        
                $response = Invoke-WebRequest -Method GET -Uri $workableJason.'@odata.nextlink' -Headers $headers 
        
            } else {
        
                break
            }
        
        }
        
        #endregion machineinfo
        #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

        #URI with query For MachineVulnerabilities
        $GetMachineVulnerabilitiesURL = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities"

        Write-Host "Aquiring Vulnerabilities..." -ForegroundColor Yellow

        #Request
        $response_ = Invoke-WebRequest -Method GET -Uri $GetMachineVulnerabilitiesURL -Headers $headers 

        $numberofVulnerabilities = 1
        $pageCount = 1

        #Handle paging
        while($true){

            #get json reply to check if @odata.nexlink exists in current API call result 
             $workableJason_ = $response_.Content | ConvertFrom-json
            
             foreach($obj_ in $($workableJason_.value)){

                #reseting strings for each obj
                [string]$dnsName = ""
                [string]$Tags =""
    
                #search for correct machine to get dns name and tags
                foreach($machine in $machineLogs){
    
                    if($($obj_.machineId) -eq $($machine.id)){
    
                        #ecporting Values for Name and Tags if Machine Id matches both tables
                        $dnsName = $machine.computerDnsName
                        $Tags = $machine.Tags
                    }     
                }
    
                        #create Obj for storing obj properties
                $Log = New-Object PSObject -Property @{                    
                    "Id" = $obj_.Id
                    "CVEId" = $obj_.cveId
                    "MachineId" = $obj_.machineId
                    "ComputerDnsName"= $dnsName
                    "Tags" = $Tags
                    "FixingKbId" = $obj_.fixingKbId
                    "ProductName" = $obj_.productName
                    "ProductVendor" = $obj_.productVendor
                    "ProductVersion" = $obj_.productVersion
                    "Severity" = $obj_.severity
                }

                #increment to already existing log with current info
                $Logs += $Log
    
                #progress Bar
                $pbCounter++
                Write-Progress -Activity "Processing Vulnerabilities | Vol. Number: $numberofVulnerabilities | Page: $pageCount" -CurrentOperation $obj.cveId -PercentComplete (($pbCounter / $($workableJason_.value).count) * 100)

                $numberofVulnerabilities++
   
            }
        


                ###########export CSV and Json files per page

                ##curent time for CSV filename
                $dateTime = (Get-Date).ToUniversalTime().Tostring("o")
                
                #$dateTime.Replace(':','_') -> replace method not working PWS 5.1
                #######workaround for removing : from $path_
                $splitDate =  $dateTime.Split(":")
                [string]$newdatetime=""
                foreach($value in $splitDate){
                    $newdatetime+= $value + "_"
                }
                $splitDate = $newdatetime.Split(".")
                #######Workaround finish

                #check if file has CSV extension
                $testCsv = ($path_.substring($path_.length -4))

                #if filename does not have .csv extension add it to name
                if ($($testCsv.Tolower) -eq ".csv") {
                    $path_ = ($path_.substring(0,$path_.length -4))
                }

                $path_ = $path_ + "_" + $newdatetime + ".csv"
                    
                #visual info
                Write-Host "Exporting csv..." -ForegroundColor Yellow

                #export log to csv
                $Logs | Export-CSV -Path $path_ -NoTypeInformation -Encoding UTF8

                #visual info of script termination
                Write-Host "CSV file exported to $path_" -ForegroundColor Green
                
                #visual info
                Write-Host "Exporting Json..." -ForegroundColor Yellow             

                #replace .csv with .Json in full file path
                $path_ = $path_.Substring(0,($path_.Length -4)) + ".Json" 

                $Logs | ConvertTo-Json | Out-File $path_

                #visual info of script termination
                Write-Host "Json file exported to $path_" -ForegroundColor Green

                #clear logs for next export
                $Logs = @()

                ###########export CSV and Json files per page END



            if($workableJason_.'@odata.nextlink') {
        
                $response_ = Invoke-WebRequest -Method GET -Uri $workableJason_.'@odata.nextlink' -Headers $headers 

                $pbcounter = 0

                $pageCount++
        
            } else {
        
                break
            }
        
        }      
                
        #visual info of script termination
        Write-Host "Finished!" -ForegroundColor Green

    }
    catch {
        #catch exception to output
        Write-Output $_
    }

}else {
    #null or empty csv fila path
    write-output "File Path cannot be null or empty! Exiting..."
    
}
