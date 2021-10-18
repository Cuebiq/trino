package io.trino.spi.security.SystemAccessControl



test_checkCanImpersonateUser{
    checkCanImpersonateUser with input as {"principal":{"name": "admin"}}
}

test_checkCanSetUser{
    checkCanSetUser with input as {"principal":{"name": "admin"}}
}

test_checkCanImpersonateUser_false {
    not checkCanImpersonateUser with input as {"principal":{"name":"user1"},"userName":"user2"}
}

test_checkCanImpersonateUser_true {
    checkCanImpersonateUser with input as {"principal":{"name":"user1"},"userName":"user1"}
}




