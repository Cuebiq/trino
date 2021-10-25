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

    private List<String> methodsToExclude = new ArrayList<>();;

    public OpaConfig url(String url)
    {
        this.url = url;
        return this;
    }

    @Config("opa.url")
    public void setUrl(String url)
    {
        this.url = url;
    }

    public String getUrl()
    {
        return url;
    }

    public OpaConfig opaPackage(String opaPackage)
    {
        this.opaPackage = opaPackage;
        return this;
    }

    @Config("opa.rules_package")
    public void setOpaPackage(String opaPackage)
    {
        this.opaPackage = opaPackage;
    }

    public String getOpaPackage()
    {
        return opaPackage;
    }

    public OpaConfig methodsToInclude(List<String> methodsToInclude)
    {
        this.methodsToInclude = methodsToInclude;
        return this;
    }

    @Config("opa.methods.include")
    public void setMethodsToInclude(String methodsToInclude)
    {
        this.methodsToInclude = (methodsToInclude == null) ? null : SPLITTER.splitToList(methodsToInclude);
    }

    public List<String> getMethodsToInclude()
    {
        return methodsToInclude;
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
