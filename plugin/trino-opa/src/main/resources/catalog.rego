package io.trino.spi.security.SystemAccessControl

filterCatalogs[catalogs]{
   catalogs = ["tpch","jmx"][_]
}

checkCanAccessCatalog[exception]{
    not allowCatalog
    exception = concat(" ",["cannot access to catalog",input.catalogName])
}

allowCatalog{
    filterCatalogs[_] = input.catalogName
}
