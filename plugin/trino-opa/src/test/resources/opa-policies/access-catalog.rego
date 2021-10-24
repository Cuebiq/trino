package io.trino.spi.security.SystemAccessControl

catalog_rules = data.rules.catalogs { data.rules.catalogs } else = [{"catalog": ".*"}]


filterCatalogs[catalog]{
    can_access_catalog(input.catalogs[i],"READ_ONLY")
    anyCatalogPermissionsRule(catalog)
    catalog = input.catalogs[i]
}


anyCatalogPermissionsRule(catalog)
{
    match(schema_rules[i],"catalog",catalog)
    match(schema_rules[i],"user",input.context.identity.user)
    matchAnyInArray(schema_rules[i],"group",input.context.identity.groups)
    object.get(schema_rules[i],"owner",false) == true
}else {
    match(table_rules[i],"catalog",catalog)
    match(table_rules[i],"user",input.context.identity.user)
    matchAnyInArray(table_rules[i],"group",input.context.identity.groups)
    count(object.get(table_rules[i],"privileges",[])) > 0
} else {
    match(catalog_session_properties_rules[i],"catalog",catalog)
    match(catalog_session_properties_rules[i],"user",input.context.identity.user)
    matchAnyInArray(catalog_session_properties_rules[i],"group",input.context.identity.groups)
    object.get(catalog_session_properties_rules[i],"allow",false) = true
}


default can_access_catalog(catalog, access_mode) = false
can_access_catalog(catalog, access_mode) = access
{
    access = match_access_mode(rule_access_mode(filtered_catalog_rules(catalog)[0]),access_mode)
}

filtered_catalog_rules(catalog) = [r|r = catalog_rules[i];
    match(catalog_rules[i],"catalog",catalog)
    match(catalog_rules[i],"user",input.context.identity.user)
    matchAnyInArray(catalog_rules[i],"group",input.context.identity.groups)
]

requiredCatalogAccess(requiredPrivilege) = "READ_ONLY"{
    ["SELECT","GRANT_SELECT"][_] == requiredPrivilege
} else = "ALL"

match_access_mode(rule_access,request_access)
{
	request_access == "READ_ONLY"
    rule_access == "ALL"
}

match_access_mode(rule_access,request_access)
{
	request_access == rule_access
}

rule_access_mode(catalog_rule) = access_mode
{
	access_mode = decode_access_mode(catalog_rule.allow)
}else = "ALL"

default decode_access_mode(am) = "NONE"

decode_access_mode(am) = string_format{
	am == true
    string_format = "ALL"
}
decode_access_mode(am) = string_format{
	am == false
    string_format = "NONE"
}
decode_access_mode(am) = string_format{
	upper(am) == ["ALL","READ_ONLY","NONE"][_]
    string_format = upper(am)
}
