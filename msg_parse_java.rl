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
import static sip.common.lookAheadWSP;
import static sip.common.whitespace;
import static sip.common.lastAddr;
import static sip.uri_parse.ParseURI;

public class msg_parse {

%% machine msg;
%% include sip "sip.rl";
%% write data;

// ParseMsg turns a SIP message byte slice into a data structure.
public static ParseResult ParseMsg(byte[] data, int len) {
    ParseResult ret = new ParseResult();
    if (data.length == 0) {
        return ret;
    }
    Msg msg = new Msg();
    // viap := &msg.Via
    Via viap = msg.Via;
    //cs := 0
    //p := 0
    //pe := len(data)
    //eof := len(data)
    int cs = 0, p = 0, pe = len, eof = len;
    byte[] buf = new byte[512]; //buf := make([]byte, len(data))
    //amt := 0
    //mark := 0
    //clen := 0
    int amt = 0, mark = 0, clen = 0;
    byte[] ctype = null; // ctype := ""
    byte[] name = null; //var name string
    byte hex = 0; //var hex byte
    byte[] value = null; //var value *string
    Via via = null; //var via *Via
    Addr addrp = null; //var addrp **Addr
    Addr addr = null; //var addr *Addr

    %% main := Message;
    %% write init;
    %% write exec;

    if (cs < msg_first_final) {
        if (p == pe) {
            System.out.println("MsgIncompleteError, cs " + cs);
            ret.checkLen = p;
            return ret;
        }
        else {
            System.out.println("MsgParseError, cs = " + cs + " offset p: %d" + p);
            ret.checkLen = p;
            return ret;
        }
    }

    if (clen > 0) {
        if (clen > (len - p)) {
            System.out.println("Content-Length incorrect " + clen + " != " + (len - p));
        }
        // msg->Payload = new Payload{ctype, std::string(p, clen)};
        buf = new byte[clen];
        System.arraycopy(data, p, buf, 0, clen);
        msg.Payload = new Payload(ctype, buf);
    }
    ret.checkLen = p;
    ret.msg = msg;
    return ret;
}
}

%%{
    machine sip_act;

    # p????????????????????????
    action hold {
        fhold;
    }

    # p?????????????????????cs????????????????????????????????????????????????
    action break {
        fbreak;
    }

    # ????????????????????????????????????????????????mark?????????
    # ??????????????????????????????????????????????????????
    action mark {
        mark = p;
    }

    # ?????????????????????p????????????????????????????????????????????????
    # ????????? p = (mark) - 1;
    action backtrack {
        fexec mark;
    }

    # amt ????????????
    action start {
        amt = 0;
    }

    # ??????????????????????????????????????????????????????
    action append {
        buf[amt] = fc;
        amt++;
    }

    # ?????????????????????????????????
    action space {
        buf[amt] = ' ';
        amt++;
    }

    # ???16?????????????????????????????????16???????????????????????????????????????hex??????
    action hexHi {
        hex = (byte) (unhex(data[p]) * 16);
    }

    # ???????????????16???????????????????????????16??????????????????hex?????????????????????buf????????????
    action hexLo {
        hex += unhex(fc);
        buf[amt] = hex;
        amt++;
    }

    # ??????????????????????????????????????????????????????
    action Method {
        // msg.Method = string(data[mark:p])
        msg.Method = new byte[p-mark];
        System.arraycopy(data, mark, msg.Method, 0, p-mark);
    }

    # ??????SIP????????????
    action VersionMajor {
        msg.VersionMajor = (byte) (msg.VersionMajor * 10 + (data[p] - 0x30));
    }

    # ??????SIP????????????
    action VersionMinor {
        msg.VersionMinor = (byte) (msg.VersionMinor * 10 + (data[p] - 0x30));
    }

    # ????????????URI???????????????URI???????????????????????????????????????
    action RequestURI {
		byte[] tmp = new byte[p-mark];
        System.arraycopy(data, mark, tmp, 0, p-mark);
		msg.Request = ParseURI(tmp, p - mark);
		if (msg.Request == null) {
			ret.checkLen = p;
			return ret;
		}
    }

    # ???????????????????????????10????????????
    action StatusCode {
        msg.Status = msg.Status * 10 + ((data[p]) - 0x30);
    }

    # ??????????????????????????????????????????Reason
    action ReasonPhrase {
        //msg.Phrase = string(buf[0:amt])
		msg.Phrase = new byte[amt];
        System.arraycopy(buf, 0, msg.Phrase, 0, amt);
    }

    # ????????????Via??????
    action ViaNew {
        via = new Via();
    }

    # viap = via->next, via = null
    action Via {
        //*viap = via
        //viap = &via.Next
        //via = nil;
        if (viap == null) {
            msg.Via = via;
            viap = msg.Via;
        }
        else {
            viap.Next = via;
            viap = via;
        }
        via = null;
    }

    # ???????????????????????????via.protocol
    action ViaProtocol {
        // via.Protocol = string(data[mark:p])
        via.Protocol = new byte[p-mark];
        System.arraycopy(data, mark, via.Protocol, 0, p-mark);
    }

    # ???????????????????????????via.version
    action ViaVersion {
        //via.Version = string(data[mark:p])
		via.Version = new byte[p-mark];
        System.arraycopy(data, mark, via.Version, 0, p-mark);
    }

    # ?????????via.transport
    action ViaTransport {
        //via.Transport = string(data[mark:p])
		via.Transport = new byte[p-mark];
		System.arraycopy(data, mark, via.Transport, 0, p-mark);
    }

    # ?????????via.Host
    action ViaHost {
        //via.Host = string(data[mark:p])
		via.Host = new byte[p-mark];
		System.arraycopy(data, mark, via.Host, 0, p-mark);
    }

    # ?????????via.port
    action ViaPort {
        via.Port = via.Port * 10 + ((data[p]) - 0x30);
    }

    # ?????????????????????via.param
    action ViaParam {
        //via.Param = &Param{name, string(buf[0:amt]), via.Param}
        byte[] tmp = new byte[amt];
        System.arraycopy(buf, 0, tmp, 0, amt);
        via.Param = new Param(name, tmp, via.Param);
    }

    # ?????????xheader???????????????SIP?????????
    action gxh {
        fhold;
        if (fc != '\n') fhold;
        fgoto xheader;
    }

    # ????????????????????????????????????????????????name?????????
    action name {
        //name = string(data[mark:p])
		name = new byte[p-mark];
        System.arraycopy(data, mark, name, 0, p-mark);
    }

    # ????????????????????????????????????????????????
    action value {{
        //b := data[mark:p - 1]
        //if value != nil {
        //    *value = string(b)
        //} else {
        //    msg.XHeader = &XHeader{name, b, msg.XHeader}
        //}
		byte[] b = new byte[p - mark - 1];
		System.arraycopy(data, mark , b, 0, p-mark-1);
        msg.XHeader = new XHeader(name, b, msg.XHeader);
    }}

    #
    action AddrNew {
        // addr = new(Addr)
        addr = new Addr();
    }

    # ???????????????????????????????????????????????????
    action AddrQuotedDisplay {
        // addr.Display = string(buf[0:amt])
		addr.Display = new byte[amt];
		System.arraycopy(buf, 0, addr.Display, 0, amt);
	}

    # ??????????????????????????????????????????????????????
    action AddrUnquotedDisplay {{
//        end := p
//        for end > mark && whitespacec(data[end - 1]) {
//            end--
//        }
//        addr.Display = string(data[mark:end])
		int end = p;
		while(end > mark && whitespace(data[end-1])) {
			end--;
		}
		addr.Display = new byte[end-mark];
		System.arraycopy(data, mark, addr.Display, 0, end-mark);
    }}

    #
    action AddrUri {
//        addr.Uri, err = ParseURI(data[mark:p])
//        if err != nil { return nil, err }
		byte[] tmp = new byte[p-mark];
		System.arraycopy(data, mark, tmp, 0, p-mark);
		addr.uri = ParseURI(tmp, p-mark);
		if (addr.uri == null) {
			ret.checkLen = p;
			return ret;
		}
    }

    #
    action AddrParam {
        //addr.Param = &Param{name, string(buf[0:amt]), addr.Param}
		byte[] tmp = new byte[amt];
		System.arraycopy(buf, 0, tmp, 0, amt);
    }

    #
    action Addr {
//        *addrp = addr
//        addrp = &addr.Next
//        addr = nil
		addrp.Next = addr;
		addrp = addr;
		addr = null;
    }

    #
    action CallID {
//        msg.CallID = string(data[mark:p])
		msg.CallID = new byte[p-mark];
        System.arraycopy(data, mark, msg.CallID, 0, p-mark);
    }

    #
    action ContentLength {
        clen = clen * 10 + ((data[p]) - 0x30);
    }

    #
    action ContentType {
//        ctype = string(data[mark:p])
		ctype = new byte[p-mark];
        System.arraycopy(data, mark, ctype, 0, p-mark);
    }

    #
    action CSeq {
        msg.CSeq = msg.CSeq * 10 + ((data[p]) - 0x30);
    }

    #
    action CSeqMethod {
//        msg.CSeqMethod = string(data[mark:p])
		msg.CSeqMethod = new byte[p-mark];
        System.arraycopy(data, mark, msg.CSeqMethod, 0, p-mark);
    }

    #
    action Expires {
        msg.Expires = msg.Expires * 10 + ((data[p]) - 0x30);
    }

    #
    action MaxForwards {
        msg.MaxForwards = msg.MaxForwards * 10 + ((data[p]) - 0x30);
    }

    #
    action MinExpires {
        msg.MinExpires = msg.MinExpires * 10 + ((data[p]) - 0x30);
    }

    action ContentLengthInit {clen = 0;}

    action ExpiresInit {msg.Expires=0;}

    action MinExpiresInit {msg.MinExpires=0;}

    action MaxForwardsInit {msg.MaxForwards=0;}

    action ValueSetNull {value = null;}

    action GetLastContactAddrP {
        if (msg.Contact == null) msg.Contact = new Addr();
        addrp=lastAddr(msg.Contact);
    }

    action GetLastFromAddrP {
        if (msg.From == null) msg.From = new Addr();
        addrp=lastAddr(msg.From);
    }

    action GetLastPAssertedIdentityAddrp {
        if (msg.PAssertedIdentity == null) msg.PAssertedIdentity = new Addr();
        addrp=lastAddr(msg.PAssertedIdentity);
    }

    action GetLastRecordRouteAddrP {
        if (msg.RecordRoute == null) msg.RecordRoute = new Addr();
        addrp=lastAddr(msg.RecordRoute);
    }

    action GetLastRemotePartyIDAddrP {
        if (msg.RemotePartyID == null) msg.RemotePartyID = new Addr();
        addrp=lastAddr(msg.RemotePartyID);
    }

    action GetLastRouteAddrP {
        if (msg.Route == null) msg.Route = new Addr();
        addrp=lastAddr(msg.Route);
    }

    action GetLastMsgAddrP {
        if (msg.To == null) msg.To = new Addr();
        addrp=lastAddr(msg.To);
    }

    action ValuePointAccept {value=msg.Accept;}

    action ValuePointAcceptContact {value=msg.AcceptContact;}

    action ValuePointAcceptEncoding {value=msg.AcceptEncoding;}

    action ValuePointAcceptLanguage {value=msg.AcceptLanguage;}

    action ValuePointAllow {value=msg.Allow;}

    action ValuePointAllowEvents {value=msg.AllowEvents;}

    action ValuePointAlertInfo {value=msg.AlertInfo;}

    action ValuePointAuthenticationInfo {value=msg.AuthenticationInfo;}

    action ValuePointAuthorization {value=msg.Authorization;}

    action ValuePointContentDisposition {value=msg.ContentDisposition;}

    action ValuePointContentLanguage {value=msg.ContentLanguage;}

    action ValueContentEncoding {value=msg.ContentEncoding;}

    action ValuePointCallInfo {value=msg.CallInfo;}

    action ValuePointDate {value=msg.Date;}

    action ValuePointErrInfo {value=msg.ErrorInfo;}

    action ValueEvent {value=msg.Event;}

    action ValuePointInReplyTo {value=msg.InReplyTo;}

    action ValuePointReplyTo {value=msg.ReplyTo;}

    action ValuePointMIMEVersion {value=msg.MIMEVersion;}

    action ValuePointOrganization {value=msg.Organization;}

    action ValuePointPriority {value=msg.Priority;}

    action ValuePointProxyAuthenticate {value=msg.ProxyAuthenticate;}

    action ValuePointProxyAuthorization {value=msg.ProxyAuthorization;}

    action ValuePointProxyRequire {value=msg.ProxyRequire;}

    action ValuePointReferTo {value=msg.ReferTo;}

    action ValuePointReferredBy {value=msg.ReferredBy;}

    action ValuePointRequire {value=msg.Require;}

    action ValuePointRetryAfter {value=msg.RetryAfter;}

    action ValuePointServer {value=msg.Server;}

    action ValuePointSubject {value=msg.Subject;}

    action ValuePointSupported {value=msg.Supported;}

    action ValuePointTimestamp {value=msg.Timestamp;}

    action ValuePointUnsupported {value=msg.Unsupported;}

    action ValuePointUserAgent {value=msg.UserAgent;}

    action ValuePointWarning {value=msg.Warning;}

    action ValuePointWWWAuthenticate {value=msg.WWWAuthenticate;}

}%%