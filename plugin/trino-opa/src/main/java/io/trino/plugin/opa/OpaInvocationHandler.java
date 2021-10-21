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
package io.trino.plugin.opa;

import com.bisnode.opa.client.OpaClient;
import com.bisnode.opa.client.query.QueryForDocumentRequest;
import com.bisnode.opa.client.rest.ObjectMapperFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import io.trino.plugin.base.security.AllowAllSystemAccessControl;
import io.trino.spi.security.AccessDeniedException;
import io.trino.spi.security.SystemAccessControl;
import io.trino.spi.security.ViewExpression;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.lang.reflect.Type;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class OpaInvocationHandler
        implements InvocationHandler
{
    private static SystemAccessControl denyAllSystemAccessControl = new SystemAccessControl() {};

    private static SystemAccessControl allowAllSystemAccessControl = new AllowAllSystemAccessControl();

    private ObjectMapper mapper;
    private final OpaClient client;
    private OpaConfig opaConfig;

    public OpaInvocationHandler(OpaConfig config)
    {
        this.opaConfig = config;

        this.mapper = ObjectMapperFactory.getInstance().create();
        mapper.registerModule(new Jdk8Module());

        SimpleModule module = new SimpleModule();
        module.addDeserializer(ViewExpression.class, new ViewExpressionDeserializer(ViewExpression.class));
        mapper.registerModule(module);


        client = OpaClient.builder()
                .opaConfiguration(config.getUrl())
                .build();
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args)
            throws Throwable
    {
        String policy = mapMethodToPolicy(method);
        if (!isPolicyConfigured(policy)) {
            return executeDefaultMethod(method, args);
        }
        Map<String, Object> input = createInputParamatersMap(method.getParameters(), args);

        Class<?> returnType = method.getReturnType();
        Type genericReturnType = method.getGenericReturnType();
        if (returnType.equals(Void.TYPE)) {
            genericReturnType = Object.class;
        }
        Object result = client.queryForDocument(new QueryForDocumentRequest(input, rulepath(policy)), genericReturnType);
        if (method.getReturnType().equals(Void.TYPE) ) {
            if(result instanceof Boolean)
            {
                if ((Boolean) result) {
                    return null;
                }
                else {
                    return throwDefaultException(method, args);
                }
            }
            else if("default-exception".equals(result))
            {
                return throwDefaultException(method, args);
            }
            else if(result instanceof String && !((String)result).isEmpty())
            {
                throw new AccessDeniedException((String)result);
            }
            else if(result instanceof List && !((List<?>) result).isEmpty())
            {
                //TODO: format message
                throw new AccessDeniedException(result.toString());
            }else
            {
                return null;
            }

        }

        return result;

    }

    private Object throwDefaultException(Method method, Object[] args)
            throws Throwable
    {
        try {
            return method.invoke(denyAllSystemAccessControl, args);
        }
        catch (InvocationTargetException ite) {
            throw ite.getCause();
        }
    }

    private String rulepath(String policy)
    {
        return "io/trino/spi/security/SystemAccessControl/" + policy;
    }

    private Object executeDefaultMethod(Method method, Object[] args)
            throws IllegalAccessException, InvocationTargetException
    {
        //TODO: make default behaviour configurable
        return method.invoke(allowAllSystemAccessControl, args);
    }

    private boolean isPolicyConfigured(String policy)
    {
        List<String> configured = opaConfig.getMethodsToCheck();
        if(opaConfig.getMethodsToCheck().isEmpty()) {
            configured = Arrays.asList(
                    "checkCanSetUser",
                    "filterCatalogs",
                    "getRowFilter",
                    "checkCanAccessCatalog",
                    "checkCanShowTables",
                    "getColumnMask"
            );
        }
        return configured.contains(policy);
    }

    private String mapMethodToPolicy(Method method)
    {
        String methodName = method.getName();
        //TODO: insert custom mapping
        return methodName;
    }

    private Map<String, Object> createInputParamatersMap(Parameter[] parameters, Object[] args)
            throws JsonProcessingException
    {
        Map<String, Object> inputObject = new HashMap<>();
        for (int i = 0; i < parameters.length; i++) {
            inputObject.put(parameters[i].getName(), args[i]);
        }
        return inputObject;
    }
}
