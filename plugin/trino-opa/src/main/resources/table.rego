package io.trino.spi.security.SystemAccessControl

default checkCanShowTables = false

checkCanShowTables {
    input.schema.catalogName = "tpch"
}
