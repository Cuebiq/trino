/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.prestosql.plugin.redshift;

import io.prestosql.plugin.jdbc.BaseJdbcConfig;
import io.prestosql.plugin.jdbc.credential.CredentialConfig;
import com.fasterxml.jackson.databind.JsonNode;
import io.airlift.configuration.Config;
import io.airlift.configuration.ConfigDescription;
import io.airlift.log.Logger;

import java.util.Arrays;
import java.util.List;

public class RedshiftConfig
        extends BaseJdbcConfig
{
    private static final Logger log = Logger.get(RedshiftConfig.class);

    protected String secretName;
    protected String jdbcAccessClass;

    public String getJdbcAccessClass()
    {
        return this.jdbcAccessClass;
    }

    @Config("jdbc.access-class")
    @ConfigDescription("This value can be used to restrict the type of operations that can be done with a specific connection. Possible values are: all, read-call, read-only.")
    public RedshiftConfig setJdbcAccessClass(String accessClass){
        final List<String> accessClasses = Arrays.asList("all", "read-call", "read-only");
        if(accessClasses.contains(accessClass)){
            this.jdbcAccessClass = accessClass.replace("-", " ");
        } else {
            log.warn("You have provided JDBC Access Class = " + accessClass);
            throw new IllegalArgumentException("JDBC Access Class was not any of: all, read call, read only.");
        }

        return this;
    }

    public String getSecretName()
    {
        return this.secretName;
    }

    @Config("redshift.secret-name")
    @ConfigDescription("name of the AWS secret to use.")
    public RedshiftConfig setSecretName(String secretName)
    {
        this.secretName = secretName;
        if (this.secretName == null || this.secretName.isEmpty()) {
            throw new IllegalArgumentException("Redshift secret name was null or empty!");
        }

        return this;
    }
}
