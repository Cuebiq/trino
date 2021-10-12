package io.trino.spi.security.SystemAccessControl

inputjson := input

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


filterCatalogs[catalogs]{
    catalogs:={"tpch"}
}

default getColumnMask = []

getRowFilter[viewExpression]{
    viewExpression={
        "identity": input.context.identity.user,
        "catalog":"tpch",
        "schema": "sf1",
        "expression": concat("",["nationkey in(",filterNations[_],")"])
    }
}

roles = ["20","21","22"]# input.context.identity.user_roles

filterNations[nations]{
	nations = concat(",", roles)
}
