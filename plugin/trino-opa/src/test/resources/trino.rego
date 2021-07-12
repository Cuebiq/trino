package io.trino.spi.security.SystemAccessControl

inputjson := input

default checkCanSetUser = false
#deprecated
checkCanSetUser {
    checkCanImpersonateUser
}

default checkCanImpersonateUser = false

checkCanImpersonateUser = true {
    input.context.identity.user == "admin"
}
checkCanImpersonateUser {
    input.context.identity.user == input.username
}


