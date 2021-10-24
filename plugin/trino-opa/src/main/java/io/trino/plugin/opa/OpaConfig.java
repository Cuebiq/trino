package io.trino.plugin.opa;

import io.airlift.configuration.Config;

import java.util.ArrayList;
import java.util.List;

public class OpaConfig
{
    private String url;

    private String opaPackage = "io/trino/spi/security/SystemAccessControl/";

    private List<String> methodsToCheck = new ArrayList<>();


    @Config("opa.url")
    public OpaConfig url(String url)
    {
        this.url = url;
        return this;
    }

    public String getUrl()
    {
        return url;
    }

    @Config("opa.rules_package")
    public OpaConfig opaPackage(String opaPackage)
    {
        this.opaPackage = opaPackage;
        return this;
    }

    public String getOpaPackage()
    {
        return opaPackage;
    }

    public OpaConfig methodsToCheck(List<String> methodsToCheck)
    {
        this.methodsToCheck = methodsToCheck;
        return this;
    }

    public List<String> getMethodsToCheck()
    {
        return methodsToCheck;
    }
}
