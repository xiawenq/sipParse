// -*-go-*-
// Copyright 2020 Justine Alexandra Roberts Tunney
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sip

import (
    "bytes"
    "errors"
    "fmt"
)

%%{
    machine uri_parse_act;
    action start {
        amt = 0
    }

    action append {
        buf[amt] = fc
        amt++
    }

    action hexHi {
        hex = unhex(fc) * 16
    }

    action hexLo {
        hex += unhex(fc)
        buf[amt] = hex
        amt++
    }

    action goto_uriSansUser {
        fgoto uriSansUser;
    }

    action goto_uriWithUser {
        fgoto uriWithUser;
    }

    action scheme {
        uri.Scheme = string(buf[0:amt])
    }

    action user {
        uri.User = string(buf[0:amt])
    }

    action pass {
        uri.Pass = string(buf[0:amt])
    }

    action host {
        uri.Host = string(buf[0:amt])
    }

    action port {
        uri.Port = uri.Port * 10 + uint16(fc - 0x30)
    }

    action b1 {
        b1 = string(buf[0:amt])
        amt = 0
    }

    action b2 {
        b2 = string(buf[0:amt])
        amt = 0
    }

    action lower {
        if 'A' <= fc && fc <= 'Z' {
            buf[amt] = fc + 0x20
        } else {
            buf[amt] = fc
        }
        amt++
    }

    action param {
        uri.Param = &URIParam{b1, b2, uri.Param}
    }

    action header {
        uri.Header = &URIHeader{b1, b2, uri.Header}
    }
}%%

%% machine uri;

%%{
    include uri_parse_core "uri_parse.rl";
    uriSansUser    := uriSansUserCore;
    uriWithUser    := uriWithUserCore;

}%%

%% write data;

// ParseURI turns a a SIP URI byte slice into a data structure.
func ParseURI(data []byte) (uri *URI, err error) {
    if data == nil {
        return nil, nil
    }
    uri = new(URI)
    cs := 0
    p := 0
    pe := len(data)
    eof := len(data)
    buf := make([]byte, len(data))
    amt := 0
    var b1, b2 string
    var hex byte

    %% write init;
    if bytes.IndexByte(data, '@') == -1 {
        cs = uri_en_uriSansUser;
    } else {
        cs = uri_en_uriWithUser;
    }
    %% write exec;

    if cs < uri_first_final {
        if p == pe {
            return nil, errors.New(fmt.Sprintf("Incomplete URI: %s", data))
        } else {
            return nil, errors.New(fmt.Sprintf("Error in URI at pos %d: %s", p, data))
        }
    }
    return uri, nil
}