package io.trino.spi.security.SystemAccessControl



default can_access_catalog(catalog, access_mode) = false
can_access_catalog(catalog, access_mode) = access
{
    match(catalog_rules[i],"catalog",catalog)
    match(catalog_rules[i],"user",input.context.identity.user)
    matchAnyInArray(catalog_rules[i],"group",input.context.identity.groups)
    access = match_access_mode(rule_access_mode(catalog_rules[i]),access_mode)
}

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
	am == ["ALL","READ_ONLY","NONE"][_]
    string_format = am
}
