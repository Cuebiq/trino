package io.trino.spi.security.SystemAccessControl

system_information_rules = data.rules.system_information {data.rules.system_information} else = []
system_session_properties_rules  = data.rules.system_session_properties {data.rules.system_session_properties} else = []
catalog_session_properties_rules  = data.rules.catalog_session_properties {data.rules.catalog_session_properties} else = []

default checkCanReadSystemInformation = false
checkCanReadSystemInformation = checkCanSystemInformation(input.context.identity.user,"read")

default checkCanWriteSystemInformation = "Cannot write system information"
checkCanWriteSystemInformation = checkCanSystemInformation(input.context.identity.user,"write")


default checkCanSystemInformation(user,requiredAccess) = false
checkCanSystemInformation(user,requiredAccess) = concat(" ",["Cannot", requiredAccess ,"system information"]) {
    count(system_information_rules) == 0
}

checkCanSystemInformation(user,requiredAccess)
{
    filtered_sys_inf_rules(user)[0].allow[_] == requiredAccess
}

filtered_sys_inf_rules(user) = [r| r = system_information_rules[x];
    match(system_information_rules[x],"user", user)
]

default checkCanSetSystemSessionProperty = false
checkCanSetSystemSessionProperty{
    object.get(filtered_sys_session_prop(input.propertyName)[0],"allow",false)
}

filtered_sys_session_prop(property) = [p|p = system_session_properties_rules[x];
    match(system_session_properties_rules[x],"user", input.context.identity.user)
    matchAnyInArray(system_session_properties_rules[x],"group",input.context.identity.groups)
    match(system_session_properties_rules[x],"property", property)
]

default checkCanSetCatalogSessionProperty = false
checkCanSetCatalogSessionProperty{
    object.get(filtered_catalog_session_prop(input.catalogName, input.propertyName)[0],"allow",false)
}

filtered_catalog_session_prop(catalog,property) = [p|p = system_session_properties_rules[x];
    can_access_catalog(catalog, "READ_ONLY")
    match(catalog_session_properties_rules[x],"user", input.context.identity.user)
    matchAnyInArray(catalog_session_properties_rules[x],"group",input.context.identity.groups)
    match(catalog_session_properties_rules[x],"catalog", catalog)
    match(catalog_session_properties_rules[x],"property", property)
]

