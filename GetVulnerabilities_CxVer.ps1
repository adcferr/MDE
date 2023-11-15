#################################################################################
#DISCLAIMER: This is not an official PowerShell Script. We designed it specifically for the situation you have encountered right now.#Please do not modify or change any preset parameters. 
#Please note that we will not be able to support the script if it is changed or altered in any way or used in a different situation for other means.
#This code sample is provided "AS IT IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#This sample is not supported under any Microsoft standard support program or service.. 
#Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. #The entire risk arising out of the use or performance of the sample and documentation remains with you. 
#In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, 
#or other pecuniary loss) arising out of  the use of or inability to use the sample or documentation, even if Microsoft has been advised of the possibility of such damages.
#################################################################################

#################################################################################

Clear-Host

#request path to save csv file
$path_ = Read-Host "Full file path for csv output (Filename included) "

#log keep for CSV build
$Logs = @()

#initialize Progress bars
$pbCounter = 0

if(!([string]::IsNullOrEmpty($path_) )) {
    #if $path is not null or empty

    #check if file has CSV extension
    $testCsv = ($path_.substring($path_.length -4))

    #if filename does not have .csv extension add it to name
    if ($($testCsv.Tolower) -ne ".csv") {
        $path_ += ".csv"
    }

    try {
        
        #setting vars for test
        $grantType = "client_credentials" #connection flow
        $clientId = Read-host "App Id "  #id 
        $clientSecret = Read-host "App Secret " #secret 
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

        Write-Host "Connecting..." -ForegroundColor Yellow

        #URI with query For MachineVulnerabilities
        $GetMachineVulnerabilitiesURL = "https://api.securitycenter.microsoft.com/api/vulnerabilities/machinesVulnerabilities"

        Write-Host "Aquiring Info..." -ForegroundColor Yellow

        #Request
        $response = Invoke-WebRequest -Method GET -Uri $GetMachineVulnerabilitiesURL -Headers $headers -ErrorAction Stop

        #json to workable json
        $workableJason  = $response.Content | ConvertFrom-json

        foreach($obj in $($workableJason.value)){

            $Log = New-Object PSObject -Property @{
                
                #Get Id 
                "Id" = $obj.Id
                #Get CVEId 
                "cveId" = $obj.cveId
                #get machineId
                "machineId" = $obj.machineId
                #Get fixingKbId
                "fixingKbId" = $obj.fixingKbId
                #Get productName
                "productName" = $obj.productName
                #Get ObjectId for current App
                "productVendor" = $obj.productVendor
                #get productVersion
                "productVersion" = $obj.productVersion
                #Get severity
                "severity" = $obj.severity
            }

            #increment to already existing log
            $Logs += $Log

            #progress Bar
            $pbCounter++
            Write-Progress -Activity 'Processing Vulnerabilities' -CurrentOperation $obj.cveId -PercentComplete (($pbCounter / $($workableJason.value).count) * 100)
   
        }
        #visual info
        Write-Host "Exporting csv..." -ForegroundColor Yellow

        #export log to csv
        $Logs | Export-CSV -Path $path_ -NoTypeInformation -Encoding UTF8

        #visual info of script termination
        Write-Host "CSV file exported to $path_" -ForegroundColor Green
          
        #visual info
        Write-Host "Exporting Json..." -ForegroundColor Yellow

        #file path has an extension to be replaced with .json
        if ($($testCsv.Tolower) -ne "Json") {

            #replace .csv with .Json in full file path
            $path_ = $path_.Substring(0,($path_.Length -4)) + ".Json"

        }else {

            #just add json extension to filename
            $path_ = $path_ + ".Json"
        }

        $workableJason | ConvertTo-Json | Out-File $path_

        #visual info of script termination
        Write-Host "Json file exported to $path_" -ForegroundColor Green
        
        #visual info of script termination
        Write-Host "Finished!" -ForegroundColor Green

    }
    catch {
        <#Do this if a terminating exception happens#>
        Write-Output $_
    }

}else {
    #null or empty csv fila path
    write-output "File Path cannot be null or empty! Exiting..."
    
}
