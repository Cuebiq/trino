package io.trino.spi.security.SystemAccessControl


default checkCanSetUser = false
#deprecated
checkCanSetUser {
    checkCanImpersonateUser
}

default checkCanImpersonateUser = false

checkCanImpersonateUser = true {
    input.principal.name == "admin"
}
checkCanImpersonateUser {
    input.principal.name == input.userName
}
