package com.hellocmu.picoctf;
public class FlagstaffHill {

    public FlagstaffHill()
    {
        return;
    }

    public static String getFlag(String p2, android.content.Context p3)
    {
        android.util.Log.i("PICO", com.hellocmu.picoctf.FlagstaffHill.paprika(p2));
        return "Not Today...";
    }

    public static native String paprika(String p0);
}
