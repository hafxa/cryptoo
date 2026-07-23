Write-Host 'Hello World'

foreach($line in Get-Content .\first.txt){

    $firstname = $line.split(' ')[0]
    $lastname = $line.split(' ')[1]
    #We are also creating a username for simplicity
    $usr = ($line[0] + $lastname).tolower()

    Write-Host $lastname
    #Just randomly generating a password
    $pass = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_})

    Write-Host $password
    #Verifying that the user does not already exist
    if (!(Get-AdUser -Filter "sAMAccountName -eq '$($line)'")) {
        New-AdUser -Name $line
                   -UserPrincipalName $usr
                   -GivenName $firstname
                   -Surname $lastname
                   -AccountPassword (ConvertTo-SecureString -AsPlainText $pass -Force)
                   -ChangePasswordAtLogon $true
                   -Enabled $true
        
    }
}

