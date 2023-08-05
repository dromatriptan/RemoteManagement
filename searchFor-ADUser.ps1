function GetUser {
    param([String]$SAMAccountName)

    $root = [ADSI]"LDAP://OU=Accounts,DC=DOMAIN,DC=local"
    $searcher = [adsisearcher]"(&(objectcategory=person)(samaccountname=$SAMAccountName))"
    $searcher.SearchRoot = $root
    $searrcher.PageSize = 9999
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $users = $searcher.FindAll()
    return $users | Select-Object -Property @{Name = "DisplayName"; Expression={$_.Properties["name"]}}
}

