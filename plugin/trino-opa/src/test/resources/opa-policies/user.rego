package io.trino.spi.security.SystemAccessControl

inpersonation_rules = data.rules.impersonation {  data.rules.impersonation } else = []


#deprecated always return true use checkCanImpersonateUser and mapping_user
checkCanSetUser = true

default checkCanImpersonateUser = false
checkCanImpersonateUser{
    principalName := input.context.identity.user
    user := input.userName
    object.get(filtered_impersonation_rules(principalName,user)[0],"allow",true)
}

filtered_impersonation_rules(principal,user) = [ r| r = inpersonation_rules[x];
    match(r,"original_user",principal)
    match(r,"new_user",user)
]



