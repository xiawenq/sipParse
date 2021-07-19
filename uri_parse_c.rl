//
// Created by xiawq on 2021/7/19.
//

#include "common.h"

%% machine uri;

%%{
    include uri_parse_core "uri_parse.rl";
    uriSansUser    := uriSansUserCore;
    uriWithUser    := uriWithUserCore;
}%%


// ParseURI turns a a SIP URI byte slice into a data structure.
URI *ParseURI(char *data, int len) {
    %% write data;

    if (!data) {
        return 0;
    }
    URI *uri = new URI;
    int cs = 0;
    char *p = data, *pe = data + len, *eof = data + len;
    char *buf = (char*) malloc(len);
    for (int i = 0; i < len; i++) {buf[i] = '\0';}
    int amt = 0;
    std::string b1, b2;
    int8_t hex = 0;

    %% write init;
    cs = uri_en_uriSansUser;
    for (int i = 0; i < len; i++) {
        if (data[i] == '@') {
            cs = uri_en_uriWithUser;
            break;
        }
    }
    %% write exec;

    free(buf);
    if (cs < uri_first_final) {
        if (p == pe) {
            printf("Incomplete URI: %s\n", data);
            delete uri;
            uri = 0;
        }
        else {
            printf("Error in URI at pos %d: %s\n", p - data, data);
            delete uri;
            uri = 0;
        }
    }
    return uri;
}

%%{
    machine uri_parse_act;
    action start {
        amt = 0;
    }

    action append {
        buf[amt] = fc;
        amt++;
    }

    action hexHi {
        hex = unhex(fc) * 16;
    }

    action hexLo {
        hex += unhex(fc);
        buf[amt] = hex;
        amt++;
    }

    action goto_uriSansUser {
        fgoto uriSansUser;
    }

    action goto_uriWithUser {
        fgoto uriWithUser;
    }

    action scheme {
        // uri.Scheme = string(buf[0:amt])
        uri->Scheme.assign(&buf[0], amt);
    }

    action user {
        // uri.User = string(buf[0:amt])
        uri->User.assign(&buf[0], amt);
    }

    action pass {
        // uri.Pass = string(buf[0:amt])
        uri->Pass.assign(&buf[0], amt);
    }

    action host {
        // uri.Host = string(buf[0:amt])
        uri->Host.assign(&buf[0], amt);
    }

    action port {
        // uri.Port = uri.Port * 10 + uint16(fc - 0x30)
        uri->Port = uri->Port * 10 + uint16_t(fc - '0');
    }

    action b1 {
        // b1 = string(buf[0:amt])
        // amt = 0
        b1.assign(&buf[0], amt);
        amt = 0;
    }

    action b2 {
        // b2 = string(buf[0:amt])
        // amt = 0
        b2.assign(&buf[0], amt);
        amt = 0;
    }

    action lower {
        // if 'A' <= fc && fc <= 'Z' {
        //     buf[amt] = fc + 0x20
        // } else {
        //     buf[amt] = fc
        // }
        // amt++
        if ('A' <= fc && fc <= 'Z') {
            buf[amt] = fc + 0x20;
        }
        else {
            buf[amt] = fc;
        }
        amt++;
    }

    action param {
        // uri.Param = &URIParam{b1, b2, uri.Param}
        uri->Param = new URIParam{b1, b2, uri->Param};
    }

    action header {
        // uri.Header = &URIHeader{b1, b2, uri.Header}
        uri->Header = new URIHeader{b1, b2, uri->Header};
    }
}%%