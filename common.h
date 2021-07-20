//
// Created by xiawq on 2021/7/19.
//

#ifndef SIPPARSE_COMMON_H
#define SIPPARSE_COMMON_H

#include <string>

class URIHeader {
public:
    std::string Name;
    std::string Value;
    URIHeader   *Next = 0;

    ~URIHeader() {
        if (Next) {
            delete Next;
        }
    }
};

class URIParam {
public:
    std::string Name;
    std::string Value;
    URIParam    *Next = 0;

    ~URIParam() {
        if (Next)
            delete Next;
    }
};

class URI {
public:
    std::string Scheme;     // e.g. sip, sips, tel, etc.
    std::string User;       // e.g. sip:USER@host
    std::string Pass;       // e.g. sip:user:PASS@host
    std::string Host;       // e.g. example.com, 1 .2.3.4, etc.
    uint16_t    Port = 0;   // e.g. 5060, 80, etc.
    URIParam    *Param = 0; // e.g. ;isup-oli=00;day=tuesday
    URIHeader   *Header = 0;// e.g. ?subject=project%20x&lol=cat

    ~URI() {
        if (Param)
            delete Param;
        if (Header)
            delete Header;
    }
};

typedef struct Payload {
    std::string Type;
    std::string Data;
}Payload;

typedef struct UDPAddr {
    std::string Ip;
    int Port = 0;
    std::string Zone;   // IPv6 scoped addressing zone
}UDPAddr;

// Param is a linked list of ;key="values" for Addr/Via parameters.
class Param {
public:
    std::string Name;
    std::string Value;
    Param       *Next = 0;

    ~Param() {
        if (Next)
            delete Next;
    }
};

// Represents a SIP Address Linked List
class Addr {
public:
    URI         *Uri = 0;   // never nil
    std::string Display;    // blank if not specified
    Param       *Param = 0; // these look like ;key=lol;rport;key=wut
    Addr        *Next = 0;  // for comma separated lists of addresses

    ~Addr() {
        if (Uri)
            delete Uri;
        if (Param)
            delete Param;
        if (Next)
            delete Next;
    }
};

// Example: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK556f77e6
class Via {
public:
    std::string Protocol;       // should be "SIP"
    std::string Version;        // protocol version e.g. "2.0"
    std::string Transport;      // transport type e.g. "UDP"
    std::string Host;           // name or ip of egress interface
    uint16_t    Port = 0;       // network port number
    Param       *Param = 0;     // param like branch, received, rport, etc.
    Via         *Next = 0;      // pointer to next via header if any

    ~Via() {
        if (Param)
            delete Param;
        if (Next)
            delete Next;
    }
};

// XHeader is a linked list storing an unrecognized SIP headers.
class XHeader {
public:
    std::string Name;       // tokenc
    std::string Value;      // UTF8, never nil
    XHeader     *Next = 0;

    ~XHeader() {
        if (Next)
            delete Next;
    }
};

// Msg represents a SIP message. This can either be a request or a response.
// These fields are never nil unless otherwise specified.
class Msg {
public:
    uint8_t     VersionMajor = 0;
    uint8_t     VersionMinor = 0;
    std::string Method;             // Indicates type of request (if request)
    URI         *Request = 0;       // dest URI (nil if response)
    int         Status = 0;         // Indicates happiness of response (if response)
    std::string Phrase;             // Explains happiness of response (if response)
    Payload     *Payload = 0;       // stuff that comes after two line break

    // Special non-SIP fields.
    UDPAddr     *SourceAddr = 0;    // Set by transport layer as received address.

    // Important headers should be further up in the struct.
    Addr        *From = 0;          // Logical sender of message
    Addr        *To = 0;            // Logical destination of message
    Via         *Via = 0;           // Linked list of agents traversed (must have one)
    Addr        *Route = 0;         // Used for goose routing and loose routing
    Addr        *RecordRoute = 0;   // Used for loose routing
    Addr        *Contact = 0;       // Where we send response packets or nil
    std::string CallID;             // Identifies call from invite to bye
    int         CSeq = 0;           // Counter for network packet ordering
    std::string CSeqMethod;         // Helps with matching to orig message
    int         MaxForwards = 0;    // 0 has context specific meaning
    std::string UserAgent;

    // All the other RFC 3261 headers in plus some extras.
    std::string Accept;
    std::string AcceptContact;
    std::string AcceptEncoding;
    std::string AcceptLanguage;
    std::string AlertInfo;
    std::string Allow;
    std::string AllowEvents;
    std::string AuthenticationInfo;
    std::string Authorization;
    std::string CallInfo;
    std::string ContentDisposition;
    std::string ContentEncoding;
    std::string ContentLanguage;
    std::string Date;
    std::string ErrorInfo;
    std::string Event;
    int         Expires = 0;            // Seconds registration should expire.
    std::string InReplyTo;
    std::string MIMEVersion;
    int         MinExpires = 0;         // Registrars need this when responding
    std::string Organization;
    Addr        *PAssertedIdentity = 0; // P-Asserted-Identity or nil (used for PSTN ANI)
    std::string Priority;
    std::string ProxyAuthenticate;
    std::string ProxyAuthorization;
    std::string ProxyRequire;
    std::string ReferTo;
    std::string ReferredBy;
    Addr        *RemotePartyID = 0;     // Evil twin of P-Asserted-Identity.
    std::string ReplyTo;
    std::string Require;
    std::string RetryAfter;
    std::string Server;
    std::string Subject;
    std::string Supported;
    std::string Timestamp;
    std::string Unsupported;
    std::string WWWAuthenticate;
    std::string Warning;

    // Extension headers.
    XHeader *XHeader = 0;

    ~Msg() {
        delete Request;
        delete Payload;
        delete SourceAddr;
        delete From;
        delete To;
        delete Via;
        delete Route;
        delete RecordRoute;
        delete Contact;
        delete PAssertedIdentity;
        delete RemotePartyID;
        delete XHeader;
    }
};

// tool function
extern int8_t unhex(char b);
extern bool lookAheadWSP(char *data, char *p, char* pe);
extern Addr** lastAddr(Addr** addrp);
extern bool whitespacec(char c);

// Generated function from FSM Definition.
extern URI *ParseURI(char *data, int len);
extern Msg *ParseMsg(char *data, int len, int *checkLen, char *buf);
#endif //SIPPARSE_COMMON_H
