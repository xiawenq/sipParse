package sip;

import java.net.DatagramPacket;
import java.util.ArrayList;

class Param {
    public byte[] Name;
    public byte[] Value;
    public Param Next;
    public Param(byte[] name, byte[] value, Param next) {
        Name = name;
        Value = value;
        Next = next;
    }
    private String s = null;
    public String toString(String prefix) {
        if (s == null) {
            s = "";
            if (Name != null) s += prefix + new String(Name) + " = " + new String(Value) + "\n";
            if (Next != null) s += Next.toString(prefix)+ "\n";
        }
        return s;
    }
}
class Payload {
    public byte[] Type;
    public byte[] Data;

    public Payload(byte[] type, byte[] data) {
        Type = type;
        Data = data;
    }
    private String s = null;
    public String toString(String prefix) {
        if (s == null) {
            s = "";
            s += prefix + "payload type " + new String(Type) + ", length = " + Data.length + "\n";
        }
        return s;
    }
}
class UDPAddr {
    public byte[] Ip;
    public int Port;
    public byte[] Zone;
    private String s = null;
    public String toString(String prefix) {
        if (s == null) {
            s = prefix + "IP: " + (Ip != null ? new String(Ip) : "") + "\n"
                    + prefix + "Port: " + Port + "\n"
                    + prefix + "Zone: " + (Zone != null ? new String(Zone) : "") + "\n";
        }
        return s;
    }
}
class Addr {
    public URI uri;
    public byte[] Display;
    public Param Param;
    public Addr Next;
    private String s = null;
    public String toString(String prefix) {
        if (s == null) {
            s = prefix + "Uri: [" + (uri != null ? uri.toString(prefix+"\t") : "") + "]\n"
                    + prefix + "Display:" + (Display != null ? new String(Display):"") + "\n";
            if (Param != null) s += Param.toString(prefix+"\t")+"\n";
            if (Next != null) {
                s += Next.toString(prefix) + "\n";
            }

        }
        return s;
    }
}
class Via {
    public byte[] Protocol;
    public byte[] Version;
    public byte[] Transport;
    public byte[] Host;
    public int Port;
    public Param Param;
    public Via Next;
    private String s = null;
    public String toString(String prefix) {
        if (s == null) {
            s = "";
            if (Protocol != null) s += prefix + "Protocol: " + new String(Protocol) + "\n";
            if (Version != null) s += prefix + "Version: " + new String(Version) + "\n";
            if (Transport != null) s += prefix + "Transport: " + new String(Transport) + "\n";
            if (Host != null) s += prefix + "Host: " + new String(Host) + "\n";
            if (Port != 0) s += prefix + "Port: " + Port + "\n";
            if (Param != null) s += Param.toString(prefix+"\t")+"\n";
            if (Next != null) s += Next.toString(prefix)+"\n";
        }
        return s;
    }
}
class XHeader {
    public byte[] Name;
    public byte[] Value;
    public XHeader Next;
    public XHeader(byte[] name, byte[] value, XHeader next) {
        Name = name;
        Value = value;
        Next = next;
    }
    private String s = null;
    public String toString(String prefix) {
        if (s == null) {
            s = "";
            s += prefix + "Name: " + (Name != null?new String(Name):
                    "") + ", Value: " + (Value != null? new String(Value) : "") + "\n";
            if (Next != null) s += Next.toString(prefix)+"\n";
        }
        return s;
    }
}
public class Msg {
    public byte VersionMajor, VersionMinor;
    public byte[] Method;
    public URI Request;
    public int Status;
    public byte[] Phrase;
    public Payload Payload;

    public UDPAddr SourceAddr;

    public Addr From;
    public Addr To;
    public Addr Contact;
    public Addr Route;
    public Addr RecordRoute;
    public Via Via;
    public byte[] CallID;
    public int CSeq;
    public byte[] CSeqMethod;
    public int MaxForwards;
    public byte[] UserAgent;

    public byte[] Accept, AcceptContact, AcceptEncoding, AcceptLanguage;
    public byte[] AlertInfo;
    public byte[] Allow, AllowEvents;
    public byte[] AuthenticationInfo, Authorization;
    public byte[] CallInfo;
    public byte[] ContentDisposition, ContentEncoding, ContentLanguage;
    public byte[] Date;
    public byte[] ErrorInfo;
    public byte[] Event;
    public int Expires, MinExpires;
    public byte[] InReplyTo;
    public byte[] MIMEVersion;
    public byte[] Organization;
    public Addr PAssertedIdentity;
    public byte[] Priority;
    public byte[] ProxyAuthenticate, ProxyAuthorization, ProxyRequire;
    public byte[] ReferTo, ReferredBy;
    public Addr RemotePartyID;
    public byte[] ReplyTo;
    public byte[] Require;
    public byte[] RetryAfter;
    public byte[] Server;
    public byte[] Subject;
    public byte[] Supported;
    public byte[] Timestamp;
    public byte[] Unsupported;
    public byte[] WWWAuthenticate;
    public byte[] Warning;

    public XHeader XHeader;
    private String s = null;

    public String toString() {
        if (s == null) {
            s = "";
            s = s + "SIP/"+VersionMajor+"."+VersionMinor+"\n";
            if (Method != null) s += "Method: " + new String(Method)+"\n";
            if (Request != null) s += "Request: [" + Request.toString("\t")+"]\n";
            if (Status != 0) s += "Status: " + Status+"\n";
            if (Phrase != null) s += "Phrase: " + new String(Phrase)+"\n";
            if (SourceAddr != null) s += "SourceAddr: [" + SourceAddr.toString("\t")+"]\n";
            if (From != null) s += "From: [" + From.toString("\t")+"]\n";
            if (To != null) s += "To: [" + To.toString("\t")+"]\n";
            if (Via != null) s += "Via: [" + Via.toString("\t")+"]\n";
            if (Route != null) s += "Route: [" + Route.toString("\t")+"]\n";
            if (RecordRoute != null) s += "RecordRoute: [" + RecordRoute.toString("\t")+"]\n";
            if (Contact != null) s += "Contact: [" + Contact.toString("\t")+"]\n";
            if (CallID != null) s += "CallID: " + new String(CallID)+"\n";
            if (CSeq != 0) s += "CSeq: " + CSeq+"\n";
            if (CSeqMethod != null) s += "CSeqMethod: " + new String(CSeqMethod)+"\n";
            if (MaxForwards != 0) s += "MaxForwards: " + MaxForwards+"\n";
            if (UserAgent != null) s += "UserAgent: " + new String(UserAgent)+"\n";

            if (Accept != null) s += "Accept: " + new String(Accept)+"\n";
            if (Accept != null) s += "Accept: " + new String(Accept)+"\n";
            if (AcceptEncoding != null) s += "AcceptEncoding: " + new String(AcceptEncoding)+"\n";
            if (AcceptLanguage != null) s += "AcceptLanguage: " + new String(AcceptLanguage)+"\n";
            if (AlertInfo != null) s += "AlertInfo: " + new String(AlertInfo)+"\n";
            if (Allow != null) s += "Allow: " + new String(Allow)+"\n";
            if (AllowEvents != null) s += "AllowEvents: " + new String(AllowEvents)+"\n";
            if (AuthenticationInfo != null) s += "AuthenticationInfo: " + new String(AuthenticationInfo)+"\n";
            if (Authorization != null) s += "Authorization: " + new String(Authorization)+"\n";
            if (CallInfo != null) s += "CallInfo: " + new String(CallInfo)+"\n";
            if (ContentDisposition != null) s += "ContentDisposition: " + new String(ContentDisposition)+"\n";
            if (ContentEncoding != null) s += "ContentEncoding: " + new String(ContentEncoding)+"\n";
            if (ContentLanguage != null) s += "ContentLanguage: " + new String(ContentLanguage)+"\n";
            if (Date != null) s += "Date: " + new String(Date)+"\n";
            if (ErrorInfo != null) s += "ErrorInfo: " + new String(ErrorInfo)+"\n";
            if (Event != null) s += "Event: " + new String(Event)+"\n";
            if (Expires != 0) s += "Expires: " + Expires+"\n";
            if (InReplyTo != null) s += "InReplyTo: " + new String(InReplyTo)+"\n";
            if (MIMEVersion != null) s += "MIMEVersion: " + new String(MIMEVersion)+"\n";
            if (MinExpires != 0) s += "MinExpires: " + MinExpires+"\n";
            if (Organization != null) s += "Organization: " + new String(Organization)+"\n";
            if (PAssertedIdentity != null) s += "PAssertedIdentity: [" + PAssertedIdentity.toString("\t")+"]\n";
            if (Priority != null) s += "Priority: " + new String(Priority)+"\n";
            if (ProxyAuthenticate != null) s += "ProxyAuthenticate: " + new String(ProxyAuthenticate)+"\n";
            if (ProxyAuthorization != null) s += "ProxyAuthorization: " + new String(ProxyAuthorization)+"\n";
            if (ProxyRequire != null) s += "ProxyRequire: " + new String(ProxyRequire)+"\n";
            if (ReferTo != null) s += "ReferTo: " + new String(ReferTo)+"\n";
            if (ReferredBy != null) s += "ReferredBy: " + new String(ReferredBy)+"\n";
            if (RemotePartyID != null) s += "RemotePartyID: [" + RemotePartyID.toString("\t")+"]\n";
            if (ReplyTo != null) s += "ReplyTo: " + new String(ReplyTo)+"\n";
            if (Require != null) s += "Require: " + new String(Require)+"\n";
            if (RetryAfter != null) s += "RetryAfter: " + new String(RetryAfter)+"\n";
            if (Server != null) s += "Server: " + new String(Server)+"\n";
            if (Subject != null) s += "Subject: " + new String(Subject)+"\n";
            if (Supported != null) s += "Supported: " + new String(Supported)+"\n";
            if (Timestamp != null) s += "Timestamp: " + new String(Timestamp)+"\n";
            if (Unsupported != null) s += "Unsupported: " + new String(Unsupported)+"\n";
            if (WWWAuthenticate != null) s += "WWWAuthenticate: " + new String(WWWAuthenticate)+"\n";
            if (Warning != null) s += "Warning: " + new String(Warning)+"\n";
            if (XHeader != null) s += "XHeader: [" + XHeader.toString("\t")+"]\n";
        }
        return s;
    }
}
