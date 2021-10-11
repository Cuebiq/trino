package io.trino.plugin.opa;

import io.airlift.configuration.Config;

public class OpaConfig
{
    private String url;

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
}
