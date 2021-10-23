package io.trino.spi.security.SystemAccessControl

query_rules = data.rules.queries{data.rules.queries} else = []


default checkCanExecuteQuery = false
checkCanExecuteQuery = can_access_query(input.context.identity.user,"execute")

default checkCanViewQueryOwnedBy = false
checkCanViewQueryOwnedBy = can_access_query(input.context.identity.user,"view")


default checkCanKillQueryOwnedBy = false
checkCanKillQueryOwnedBy = can_access_query(input.context.identity.user,"kill")

default filterViewQueryOwnedBy = []
filterViewQueryOwnedBy = input.queryOwners{
    count(query_rules) == 0
}
filterViewQueryOwnedBy =input.queryOwners{
    can_access_query(input.context.identity.user,"view")
}


default can_access_query(user,requiredAccess) = false
can_access_query(user,requiredAccess){
    count(query_rules) == 0
}

can_access_query(user,requiredAccess)
{
    filtered_query_rules(user)[0].allow[_] == requiredAccess
}

filtered_query_rules(user) = [r| r = query_rules[x];
    match(query_rules[x],"user", user)
]
