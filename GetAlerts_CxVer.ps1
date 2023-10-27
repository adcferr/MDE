#################################################################################
#DISCLAIMER: This is not an official PowerShell Script. We designed it specifically for the situation you have encountered right now.#Please do not modify or change any preset parameters. 
#Please note that we will not be able to support the script if it is changed or altered in any way or used in a different situation for other means.
#This code sample is provided "AS IT IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#This sample is not supported under any Microsoft standard support program or service.. 
#Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. #The entire risk arising out of the use or performance of the sample and documentation remains with you. 
#In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, 
#or other pecuniary loss) arising out of  the use of or inability to use the sample or documentation, even if Microsoft has been advised of the possibility of such damages.
#################################################################################


#request path to save csv file
$path_ = Read-Host "Full file path for csv output (Filename included): "

#log keep for CSV build
$Logs = @()

#initialize Progress bars
$pbCounter = 0

#check if $path is null or empty
$checkEmptyPath = [string]::IsNullOrEmpty($path_) 

if(!$checkEmptyPath) {
    #if $path is not null or empty

    #check if file has CSV extension
    $testCsv = ($path_.substring($path_.length -4))

    #if filename does not have .csv extension add it to name
    if ($($testCsv.Tolower) -ne ".csv") {
        $path_ += ".csv"
    }

    #cx version
    $clientId = Read-Host "AppID: "
    $clientSecret = Read-host "AppSecret: "
    $tenantId =  Read-Host "Tenant: "


    $grantType = "client_credentials" #connection flow
    $oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token" 


    #*****************Alerts******************************************
    $resourceAppIdUri = 'https://securitycenter.onmicrosoft.com/windowsatpservice'

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

    #set datetime var
    $dateTime = (Get-Date).ToUniversalTime().Addhours(-48).Tostring("o")

    #uri with query for alerts
    $GetMachinesUrl = "https://api.securitycenter.microsoft.com/api/alerts"#?`$top=10&`$expand=evidence"

    #Request
    $response = Invoke-WebRequest -Method GET -Uri $GetMachinesUrl -Headers $headers -ErrorAction Stop

    #json to workable json
    $json = $response.Content | ConvertFrom-json | ConvertTo-json #workaround
    $workableJason = $json | ConvertFrom-json

    $Alerts = $($workableJason.value).count

    foreach($alert in $($workableJason.value)){
        #do actions here

        #log info
        $Log = New-Object System.Object        
        $Log | Add-Member -MemberType NoteProperty -Name "severity" -Value $alert.severity
        $Log | Add-Member -MemberType NoteProperty -Name "investigationState" -Value $alert.investigationState
        $Log | Add-Member -MemberType NoteProperty -Name "category" -Value $alert.category
        $Log | Add-Member -MemberType NoteProperty -Name "computerDnsName" -Value $alert.computerDnsName
        $Log | Add-Member -MemberType NoteProperty -Name "alertCreationTime" -Value $alert.alertCreationTime

        #increment to already existing log
        $Logs += $Log

        #progress Bar
        $pbCounter++
        Write-Progress -Activity 'Processing Alert' -CurrentOperation $alert.incidentID -PercentComplete (($pbCounter / $Alerts) * 100)
    }

    #export log to csv
    $Logs | Export-CSV -Path $path_ -NoTypeInformation -Encoding UTF8

} else {
    #null or empty csv fila path
    write-output "File Path cannot be null or empty! Exiting..."

}