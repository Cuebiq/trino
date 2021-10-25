package io.trino.spi.security.SystemAccessControl

schema_rules = data.rules.schemas {data.rules.schemas} else = [{"owner": true}]


filterSchemas[schemas]{
    check_any_schema_access(input.catalogName, input.schemaNames[i])
    schemas = input.schemaNames[i]
}

default checkCanShowSchemas = false
checkCanShowSchemas {
    check_any_catalog_access(input.catalogName)
}

default checkCanCreateSchema = false
checkCanCreateSchema {
	is_schema_owner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanDropSchema = false
checkCanDropSchema {
	is_schema_owner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanRenameSchema = false
checkCanRenameSchema{
   is_schema_owner(input.schema.catalogName,input.schema.schemaName)
   is_schema_owner(input.schema.catalogName,input.newSchemaName)
}

default checkCanSetSchemaAuthorization = false
checkCanSetSchemaAuthorization{
    is_schema_owner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanShowCreateSchema = false
checkCanShowCreateSchema
{
    is_schema_owner(input.schemaName.catalogName,input.schemaName.schemaName)
}

default checkCanGrantSchemaPrivilege = false
checkCanGrantSchemaPrivilege{
    is_schema_owner(input.schema.catalogName,input.schema.schemaName)
}

default checkCanRevokeSchemaPrivilege = false
checkCanRevokeSchemaPrivilege{
    is_schema_owner(input.schema.catalogName,input.schema.schemaName)
}


check_any_schema_access(catalog,schema)
{
    can_access_catalog(catalog,"READ_ONLY")
    has_any_catalog_schema_permissions_rule(catalog,schema)
}

has_any_catalog_schema_permissions_rule(catalog,schema)
{
    match(schema_rules[i],"catalog",catalog)
    match(schema_rules[i],"schema",schema)
    match(schema_rules[i],"user",input.context.identity.user)
    match_any_in_array(schema_rules[i],"group",input.context.identity.groups)
    object.get(schema_rules[i],"owner",false) == true
}else {
    match(table_rules[i],"catalog",catalog)
    match(table_rules[i],"schema",schema)
    match(table_rules[i],"user",input.context.identity.user)
    match_any_in_array(table_rules[i],"group",input.context.identity.groups)
    count(object.get(table_rules[i],"privileges",[])) > 0
}


