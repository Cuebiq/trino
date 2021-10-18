package io.trino.plugin.opa;

import io.airlift.configuration.Config;

import java.util.ArrayList;
import java.util.List;

public class OpaConfig
{
    private String url;

    private List<String> methodsToCheck = new ArrayList<>();

    public String getUrl()
    {
        return url;
    }

    @Config("opa.url")
    public OpaConfig setUrl(String url)
    {
        this.url = url;
        return this;
    }

    public List<String> getMethodsToCheck()
    {
        return methodsToCheck;
    }

    public void setMethodsToCheck(List<String> methodsToCheck)
    {
        this.methodsToCheck = methodsToCheck;
    }
}
