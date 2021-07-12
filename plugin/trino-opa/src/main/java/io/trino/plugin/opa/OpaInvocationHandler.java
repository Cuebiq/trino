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
import com.bisnode.opa.client.data.OpaDocument;
import com.bisnode.opa.client.query.OpaQueryApi;
import com.bisnode.opa.client.query.QueryForDocumentRequest;
import com.bisnode.opa.client.rest.ObjectMapperFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import io.trino.plugin.base.security.AllowAllSystemAccessControl;
import io.trino.spi.security.SystemAccessControl;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
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
    private OpaClient client = OpaClient.builder()
            .opaConfiguration("http://localhost:8181")
            .build();

    public OpaInvocationHandler()
    {
        this.mapper = ObjectMapperFactory.getInstance().create();
        mapper.registerModule(new Jdk8Module());

//        OpaDocument doc = new OpaDocument("/test","{json}");
//        client.createOrOverwriteDocument(doc);
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
        if (returnType.equals(Void.TYPE)) {
            returnType = Boolean.class;
        }

        Object result = client.queryForDocument(new QueryForDocumentRequest(input, rulepath(policy)), returnType);
        if (method.getReturnType().equals(Void.TYPE) && result instanceof Boolean) {
            if ((Boolean) result) {
                return null;
            }
            else {
                try {
                    return method.invoke(denyAllSystemAccessControl, args);
                }catch (InvocationTargetException ite)
                {
                    throw ite.getCause();
                }

            }
        }
        return executeDefaultMethod(method, args);

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
        List<String> configured = Arrays.asList("checkCanSetUser");
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
