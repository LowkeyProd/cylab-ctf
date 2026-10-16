package com.hellocmu.picoctf;
public final class BuildConfig {
    public static final String APPLICATION_ID = "com.hellocmu.picoctf";
    public static final String BUILD_TYPE = "debug";
    public static final boolean DEBUG = False;
    public static final String FLAVOR = "zero";
    public static final int VERSION_CODE = 1;
    public static final String VERSION_NAME = "1.0";

    static BuildConfig()
    {
        com.hellocmu.picoctf.BuildConfig.DEBUG = Boolean.parseBoolean("true");
        return;
    }

    public BuildConfig()
    {
        return;
    }
}
