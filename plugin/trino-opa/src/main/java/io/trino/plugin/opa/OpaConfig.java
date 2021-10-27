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

import com.google.common.base.Splitter;
import io.airlift.configuration.Config;

import java.util.ArrayList;
import java.util.List;

public class OpaConfig
{
    private static final Splitter SPLITTER = Splitter.on(',').trimResults().omitEmptyStrings();

    private String url;

    private String opaPackage = "io/trino/spi/security/SystemAccessControl/";

    private List<String> methodsToInclude = new ArrayList<>();

    private List<String> methodsToExclude = new ArrayList<>();

    public OpaConfig url(String url)
    {
        this.url = url;
        return this;
    }

    public String getUrl()
    {
        return url;
    }

    @Config("opa.url")
    public void setUrl(String url)
    {
        this.url = url;
    }

    public OpaConfig opaPackage(String opaPackage)
    {
        this.opaPackage = opaPackage;
        return this;
    }

    public String getOpaPackage()
    {
        return opaPackage;
    }

    @Config("opa.rules_package")
    public void setOpaPackage(String opaPackage)
    {
        this.opaPackage = opaPackage;
    }

    public OpaConfig methodsToInclude(List<String> methodsToInclude)
    {
        this.methodsToInclude = methodsToInclude;
        return this;
    }

    public List<String> getMethodsToInclude()
    {
        return methodsToInclude;
    }

    @Config("opa.methods.include")
    public void setMethodsToInclude(String methodsToInclude)
    {
        this.methodsToInclude = (methodsToInclude == null) ? null : SPLITTER.splitToList(methodsToInclude);
    }

    public List<String> getMethodsToExclude()
    {
        return this.methodsToExclude;
    }

    @Config("opa.methods.exclude")
    public void setMethodsToExclude(String methodsToExclude)
    {
        this.methodsToExclude = (methodsToExclude == null) ? null : SPLITTER.splitToList(methodsToExclude);
    }
}
