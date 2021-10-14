package io.trino.spi.security.SystemAccessControl



test_checkCanImpersonateUser{
    checkCanImpersonateUser with input as {"principal":{"name": "admin"}}
}

test_checkCanSetUser{
    checkCanSetUser with input as {"principal":{"name": "admin"}}
}

