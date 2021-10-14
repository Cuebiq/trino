package io.trino.spi.security.SystemAccessControl


test_getColumnMask{
    view_expression := getColumnMask with input as {"context":{"identity":{"user":"user1","groups":[],"principal":{"name":"user1"},"roles":{},"extraCredentials":{}},"queryId":"20211013_204003_00055_4ji8a"},"type":"varchar(117)","tableName":{"catalog":"tpch","schemaTable":{"schema":"sf1","table":"customer"}},"columnName":"acctbal"}
    view_expression.expression == "acctbal-1000000000"
}
