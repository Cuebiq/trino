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

import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.secretsmanager.AWSSecretsManager;
import com.amazonaws.services.secretsmanager.AWSSecretsManagerClientBuilder;
import com.amazonaws.services.secretsmanager.model.GetSecretValueRequest;
import com.amazonaws.services.secretsmanager.model.GetSecretValueResult;
import com.amazonaws.services.secretsmanager.model.InvalidParameterException;
import com.amazonaws.services.secretsmanager.model.InvalidRequestException;
import com.amazonaws.services.secretsmanager.model.ResourceNotFoundException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.airlift.log.Logger;

import java.io.IOException;

public class AwsSecretManager
{
    private static final Logger log = Logger.get(AwsSecretManager.class);
    AWSSecretsManager client;
    private String region = "eu-west-1";

    public AwsSecretManager()
    {
        this.setClient();
    }

    public AwsSecretManager(String region)
    {
        this.setRegion(region);
        this.setClient();
    }

    private void setClient()
    {
        String endpoints = "https://secretsmanager." + this.region + ".amazonaws.com";
        AwsClientBuilder.EndpointConfiguration config = new AwsClientBuilder.EndpointConfiguration(endpoints, this.region);
        AWSSecretsManagerClientBuilder clientBuilder = AWSSecretsManagerClientBuilder.standard();
        clientBuilder.setEndpointConfiguration(config);
        this.client = clientBuilder.build();
    }

    private void setRegion(String region)
    {
        this.region = region;
    }

    public JsonNode getSecret(String secretName)
    {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode secretsJson = null;
        GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest().withSecretId(secretName);
        GetSecretValueResult getSecretValueResponse = null;

        try {
            getSecretValueResponse = client.getSecretValue(getSecretValueRequest);
        }
        catch (ResourceNotFoundException e) {
            log.error("The requested secret " + secretName + " was not found");
        }

        catch (InvalidRequestException e) {
            log.error("The request was invalid due to: " + e.getMessage());
        }

        catch (InvalidParameterException e) {
            log.error("The request had invalid params: " + e.getMessage());
        }

        if (getSecretValueResponse == null) {
            return null;
        }

        String secret = getSecretValueResponse.getSecretString();

        if (secret != null) {
            try {
                secretsJson = objectMapper.readTree(secret);
            }
            catch (IOException e) {
                log.error("Exception while retrieving secret values: " + e.getMessage());
            }
        }
        else {
            log.error("The Secret String returned is null");
            return null;
        }
        return secretsJson;
    }
}
