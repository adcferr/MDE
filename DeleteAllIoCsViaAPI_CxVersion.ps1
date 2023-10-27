#################################################################################
#DISCLAIMER: This is not an official PowerShell Script. We designed it specifically for the situation you have encountered right now.#Please do not modify or change any preset parameters. 
#Please note that we will not be able to support the script if it is changed or altered in any way or used in a different situation for other means.
#This code sample is provided "AS IT IS" without warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and/or fitness for a particular purpose.
#This sample is not supported under any Microsoft standard support program or service.. 
#Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. #The entire risk arising out of the use or performance of the sample and documentation remains with you. 
#In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the script be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, 
#or other pecuniary loss) arising out of  the use of or inability to use the sample or documentation, even if Microsoft has been advised of the possibility of such damages.
#################################################################################


#Script to delete all Indicators in the provided tenant

#this script is built to use with API api.securitycenter.microsoft.com. 

#setting vars
$grantType = "client_credentials" #connection flow
$clientId = Read-Host "App Id "  #id for ConnectViaApp
$clientSecret = Read-Host "App Secret" -AsSecureString #secret for ConnectViaApp
$tenantId = Read-Host "Tenant Id " #swarupa tenant
$oAuthUri = "https://login.microsoftonline.com/$tenantId/oauth2/token" 

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

#URI with query
$IndicatorsListURL = "https://api.securitycenter.microsoft.com/api/indicators"

#Request
$response = Invoke-WebRequest -Method GET -Uri $IndicatorsListURL -Headers $headers -ErrorAction Stop

$json = $response.Content | ConvertTo-json 

$workableJason = $json | ConvertFrom-json

#initialize Progress bars
$pbCounter = 0

foreach ($value in $workableJason.value) {

    #progress Bar
    $pbCounter++
    Write-Progress -Activity 'Deleting IoC' -CurrentOperation $value.indicatorValue -PercentComplete ($pbCounter / $($workableJason.value).count * 100) 

    try {

        #set current indicator url for delete action
        $deleteIndicatorURL = "https://api.securitycenter.microsoft.com/api/indicators//$($value.id)"
        
        #delete action
        $deleteAction = Invoke-WebRequest -Method DELETE -Uri $deleteIndicatorURL -Headers $headers -ErrorAction Stop 

    }
    catch {

        #on error print error message
        Write-Output $_
    }

}

#visual info of termination
Write-Host "Finished!"
Write-Host "This window will now close!"
Write-Host "Bye!"
Pause

