package io.trino.spi.security.SystemAccessControl

inputjson := input

default checkCanSetUser = false
checkCanSetUser {
    input.principal.name == input.username
}

default checkCanImpersonateUser = false
checkCanImpersonateUser {
    input.context.identity.user == "admin"
}
checkCanImpersonateUser {
    input.context.identity.user == input.username
}


