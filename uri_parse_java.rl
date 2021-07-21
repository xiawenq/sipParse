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

package sip;

import static sip.common.unhex;

public class uri_parse {
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
        hex = (byte) (unhex(fc) * 16);
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
        // uri.Scheme = string(buf[0:amt]);
        uri.Scheme = new byte[amt];
        System.arraycopy(buf, 0, uri.Scheme, 0, amt);
    }

    action user {
        // uri.User = string(buf[0:amt]);
        uri.User = new byte[amt];
        System.arraycopy(buf, 0, uri.User, 0, amt);
    }

    action pass {
        // uri.Pass = string(buf[0:amt]);
        uri.Pass = new byte[amt];
        System.arraycopy(buf, 0, uri.Pass, 0, amt);
    }

    action host {
        // uri.Host = string(buf[0:amt]);
        uri.Host = new byte[amt];
        System.arraycopy(buf, 0, uri.Host, 0, amt);
    }

    action port {
        // uri.Port = uri.Port * 10 + uint16(fc - 0x30);
        uri.Port = (short) (uri.Port * 10 + (data[p] - 0x30));
    }

    action b1 {
        //b1 = string(buf[0:amt]);
        b1 = new byte[amt];
        System.arraycopy(buf, 0, b1, 0, amt);
        amt = 0;
    }

    action b2 {
        // b2 = string(buf[0:amt]);
        b2 = new byte[amt];
        System.arraycopy(buf, 0, b2, 0, amt);
        amt = 0;
    }

    action lower {
        if ('A' <= fc && fc <= 'Z') {
            buf[amt] = (byte) (data[p] + 0x20);
        } else {
            buf[amt] = fc;
        }
        amt++;
    }

    action param {
        // uri.Param = &URIParam{b1, b2, uri.Param};
        uri.Param.add(new URIParam(b1, b2));
    }

    action header {
        // uri.Header = &URIHeader{b1, b2, uri.Header};
        uri.Header.add(new URIHeader(b1, b2));
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
public static URI ParseURI(byte[] data, int len) {
    if (data.length == 0) {
        return null;
    }
    URI uri = new URI();
    int cs = 0;
    int p = 0; //p := 0
    int pe = len; // pe := len(data)
    int eof = len; // eof := len(data)
    byte[] buf = new byte[512]; //buf := make([]byte, len(data))
    int amt = 0; // amt := 0
    byte[] b1 = new byte[0], b2 = new byte[0]; // var b1, b2 string
    byte hex = 0; // var hex byte

    %% write init;
    cs = uri_en_uriSansUser;
	for (byte datum : data) {
		if (datum == '@') {
			cs = uri_en_uriWithUser;
			break;
		}
	}
    %% write exec;

    if (cs < uri_first_final) {
        if (p == pe) {
            // return nil, errors.New(fmt.Sprintf("Incomplete URI: %s", data))
            System.out.println("Incomplete URI: " + new String(data));
            return null;
        } else {
            // return nil, errors.New(fmt.Sprintf("Error in URI at pos %d: %s", p, data))
            System.out.println("Error in URI at post " + p + ": " + new String(data));
            return null;
        }
    }
    return uri;
}
}