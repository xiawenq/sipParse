package sip;

import java.util.ArrayList;

class URIParam {
    public byte[] Name;
    public byte[] Value;

    public URIParam(byte[] name, byte[] value) {
        Name = name;
        Value = value;
    }
}

class URIHeader {
    public byte[] Name;
    public byte[] Value;

    public URIHeader(byte[] name, byte[] value) {
        Name = name;
        Value = value;
    }
}

public class URI {
    public byte[]       Scheme;   // e.g. sip, sips, tel, etc.
    public byte[]       User;
    public byte[]       Pass;
    public byte[]       Host;
    public short        Port;
    public ArrayList<URIParam> Param = new ArrayList<URIParam>();
    public ArrayList<URIHeader>    Header = new ArrayList<URIHeader>();
    String s;

    public String toString(String prefix) {
        if (s == null) {
            s = "";
            s = s + prefix + "Scheme: " + (Scheme != null ? new String(Scheme) : "")+"\n";
            s = s + prefix + "User: " + (User != null ? new String(User) : "")+"\n";
            s = s + prefix + "Pass: " + (Pass != null ? new String(Pass) : "")+"\n";
            s = s + prefix + "Host: " + (Host != null ? new String(Host) : "")+"\n";
            s = s + prefix + "Port: " + (Port != 0 ? Port : "Undefined") + "\n";
            for (URIParam p : Param) {
                s = s + "Param:\n"
                        + prefix + "\tName: " + (p.Name!=null? new String(p.Name):"")+"\n"
                        + prefix + ", Value: " + (p.Value!=null? new String(p.Value):"") + '\n';
            }
            for (URIHeader h : Header) {
                s = s + "Header:\n"
                        + prefix + "\tName: " + (h.Name!=null? new String(h.Name):"")+"\n"
                        + prefix + ", Value: " + (h.Value!=null? new String(h.Value):"")+'\n';
            }
        }
        return s;
    }
}

