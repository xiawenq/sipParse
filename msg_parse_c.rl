//
// Created by xiawq on 2021/7/19.
//

#include "common.h"

%% machine msg;
%% include sip "sip.rl";
%% write data;

// ParseMsg turns a SIP message byte slice into a data structure.
Msg *ParseMsg(char *data, int len, int *checkLen, char *buf) {
    if (!data) {
        printf("data pointer null\n");
    }
    char tmp[512];
    if (!buf) {
        buf = tmp;
    }

    Msg *msg = new Msg;
    Via **viap = &msg->Via;
    int cs = 0;
    char *p = data, *pe = data+len, *eof = data+len, *mark = 0;
    int amt = 0, clen = 0;
    std::string ctype, name;
    int8_t hex;
    std::string *value;
    Via *via = 0;
    Addr *addr = 0, **addrp = 0;

    %% main := Message;
    %% write init;
    %% write exec;

    if (cs < msg_first_final) {
        if (p == pe) {
            printf("MsgIncompleteError, cs = %d\n", cs);
            delete msg; msg = 0;
        }
        else {
            printf("MsgParseError, cs = %d, offset p: %d\n", cs, p - data);
            delete msg; msg = 0;
        }
    }

    if (clen > 0) {
        if (clen > (len - (p-data))) {
            printf("Content-Length incorrect %d != %d\n", clen, len - (p-data));
        }
        msg->Payload = new Payload{ctype, std::string(p, clen)};
    }
    if (checkLen)
        *checkLen = p - data;
    return msg;
}

%%{
    machine sip_act;

    # p指针回退一个字符
    action hold {
        fhold;
    }

    # p指针后移一个，cs记录当前状态值后，退出状态机匹配
    action break {
        fbreak;
    }

    # 将当前正在处理的字符的游标保存到mark变量里
    # 一般可以在表达式起始匹配时触发该动作
    action mark {
        mark = p;
    }

    # 字符串回溯，将p回溯到给定的游标前一个字符位置。
    # 这里是 p = (mark) - 1;
    action backtrack {
        fexec mark;
    }

    # amt 变量赋值
    action start {
        amt = 0;
    }

    # 在缓冲区中追加一个当前指针指向的字符
    action append {
        buf[amt] = fc;
        amt++;
    }

    # 在缓冲区中追加一个空格
    action space {
        buf[amt] = ' ';
        amt++;
    }

    # 将16进制字符数值换算成整型16进制数值并左移一位，赋值给hex变量
    action hexHi {
        hex = unhex(fc) * 16;
    }

    # 将字符类型16进制数值换算成整型16进制数值，和hex相加，并追加在buf缓冲区中
    action hexLo {
        hex += unhex(fc);
        buf[amt] = hex;
        amt++;
    }

    # 将方法字符串从要解析的数据中拷贝出来
    action Method {
        // msg.Method = string(data[mark:p])
        msg->Method.assign(mark, p - mark);
    }

    # 解析SIP大版本号
    action VersionMajor {
        msg->VersionMajor = msg->VersionMajor * 10 + (fc - 0x30);
    }

    # 解析SIP小版本号
    action VersionMinor {
        msg->VersionMinor = msg->VersionMinor * 10 + (fc - 0x30);
    }

    # 解析请求URI，如果请求URI解析出错，直接退出其余解析
    action RequestURI {
        // msg.Request, err = ParseURI(data[mark:p])
        // if err != nil { return nil, err }
        msg->Request = ParseURI(mark, p-mark);
        //if (!msg->Request)
        //    return 0;
    }

    # 将状态码字符转换成10进制整数
    action StatusCode {
        msg->Status = msg->Status * 10 + (int(fc) - 0x30);
    }

    # 提取临时缓冲区里的字符串作为Reason
    action ReasonPhrase {
        // msg.Phrase = string(buf[0:amt])
        msg->Phrase.assign(&buf[0], amt);
    }

    # 新建一个Via对象
    action ViaNew {
        // via = new(Via)
        via = new Via;
    }

    # viap = via->next, via = null
    action Via {
        // *viap = via
        // viap = &via.Next
        // via = nil
        *viap = via;
        viap = &via->Next;
        via = 0;
    }

    # 从输入数据中提取出via.protocol
    action ViaProtocol {
        // via.Protocol = string(data[mark:p])
        via->Protocol.assign(mark, p-mark);
    }

    # 从输入数据中提取出via.version
    action ViaVersion {
        // via.Version = string(data[mark:p])
        via->Version.assign(mark ,p-mark);
    }

    # 提取出via.transport
    action ViaTransport {
        // via.Transport = string(data[mark:p])
        via->Transport.assign(mark, p-mark);
    }

    # 提取出via.Host
    action ViaHost {
        // via.Host = string(data[mark:p])
        via->Host.assign(mark, p-mark);
    }

    # 提取出via.port
    action ViaPort {
        via->Port = via->Port * 10 + (uint16_t(fc) - 0x30);
    }

    # 从缓冲区提取出via.param
    action ViaParam {
        // via.Param = &Param{name, string(buf[0:amt]), via.Param}
        via->Param = new Param{name, std::string(buf, amt), via->Param};
    }

    # 跳转到xheader状态机匹配SIP扩展头
    action gxh {
        fhold;
        if (fc != '\n') fhold;
        fgoto xheader;
    }

    # 从缓冲区中将字段名提取出来保存到name变量中
    action name {
        // name = string(data[mark:p])
        name.assign(mark, p-mark);
    }

    # 把头域字段值从输入数据中提取出来
    action value {{
    #if 0
        b := data[mark:p - 1]
        if value != nil {
            *value = string(b)
        } else {
            msg.XHeader = &XHeader{name, b, msg.XHeader}
        }
    #else
        std::string b(mark, p-mark-1);
        if (value != 0) {
            *value = b;
        }
        else {
            msg->XHeader = new XHeader{name, b, msg->XHeader};
        }
    #endif
    }}

    #
    action AddrNew {
        // addr = new(Addr)
        addr = new Addr;
    }

    # 把带双引号的地址从缓冲区中提取出来
    action AddrQuotedDisplay {
        // addr.Display = string(buf[0:amt])
        addr->Display.assign(buf, amt);
    }

    # 把不带双引号的地址从缓冲区中提取出来
    action AddrUnquotedDisplay {{
    #if 0
        end := p
        for end > mark && whitespacec(data[end - 1]) {
            end--
        }
        addr.Display = string(data[mark:end])
    #else
        char *end = p;
        while(end > mark && whitespacec(*(end-1))) {
            end--;
        }
        addr->Display.assign(mark, end-mark);
    #endif
    }}

    #
    action AddrUri {
        // addr.Uri, err = ParseURI(data[mark:p])
        // if err != nil { return nil, err }
        addr->Uri = ParseURI(mark, p-mark);
        // if (!addr->Uri)
        //     return 0;
    }

    #
    action AddrParam {
        // addr.Param = &Param{name, string(buf[0:amt]), addr.Param}
        addr->Param = new Param{name, std::string(buf, amt), addr->Param};
    }

    #
    action Addr {
        *addrp = addr;
        addrp = &addr->Next;
        addr = 0;
    }

    #
    action CallID {
        // msg.CallID = string(data[mark:p])
        msg->CallID.assign(mark, p-mark);
    }

    #
    action ContentLength {
        clen = clen * 10 + (int(fc) - 0x30);
    }

    #
    action ContentType {
        // ctype = string(data[mark:p])
        ctype.assign(mark, p-mark);
    }

    #
    action CSeq {
        msg->CSeq = msg->CSeq * 10 + (int(fc) - 0x30);
    }

    #
    action CSeqMethod {
        // msg.CSeqMethod = string(data[mark:p])
        msg->CSeqMethod.assign(mark, p-mark);
    }

    #
    action Expires {
        msg->Expires = msg->Expires * 10 + (int(fc) - 0x30);
    }

    #
    action MaxForwards {
        msg->MaxForwards = msg->MaxForwards * 10 + (int(fc) - 0x30);
    }

    #
    action MinExpires {
        msg->MinExpires = msg->MinExpires * 10 + (int(fc) - 0x30);
    }

    action ContentLengthInit {clen = 0;}

    action ExpiresInit {msg->Expires=0;}

    action MinExpiresInit {msg->MinExpires=0;}

    action MaxForwardsInit {msg->MaxForwards=0;}

    action ValueSetNull {value = 0;}

    action GetLastContactAddrP {addrp=lastAddr(&msg->Contact);}

    action GetLastFromAddrP {addrp=lastAddr(&msg->From);}

    action GetLastPAssertedIdentityAddrp {addrp=lastAddr(&msg->PAssertedIdentity);}

    action GetLastRecordRouteAddrP {addrp=lastAddr(&msg->RecordRoute);}

    action GetLastRemotePartyIDAddrP {addrp=lastAddr(&msg->RemotePartyID);}

    action GetLastRouteAddrP {addrp=lastAddr(&msg->Route);}

    action GetLastMsgAddrP {addrp=lastAddr(&msg->To);}

    action ValuePointAccept {value=&msg->Accept;}

    action ValuePointAcceptContact {value=&msg->AcceptContact;}

    action ValuePointAcceptEncoding {value=&msg->AcceptEncoding;}

    action ValuePointAcceptLanguage {value=&msg->AcceptLanguage;}

    action ValuePointAllow {value=&msg->Allow;}

    action ValuePointAllowEvents {value=&msg->AllowEvents;}

    action ValuePointAlertInfo {value=&msg->AlertInfo;}

    action ValuePointAuthenticationInfo {value=&msg->AuthenticationInfo;}

    action ValuePointAuthorization {value=&msg->Authorization;}

    action ValuePointContentDisposition {value=&msg->ContentDisposition;}

    action ValuePointContentLanguage {value=&msg->ContentLanguage;}

    action ValueContentEncoding {value=&msg->ContentEncoding;}

    action ValuePointCallInfo {value=&msg->CallInfo;}

    action ValuePointDate {value=&msg->Date;}

    action ValuePointErrInfo {value=&msg->ErrorInfo;}

    action ValueEvent {value=&msg->Event;}

    action ValuePointInReplyTo {value=&msg->InReplyTo;}

    action ValuePointReplyTo {value=&msg->ReplyTo;}

    action ValuePointMIMEVersion {value=&msg->MIMEVersion;}

    action ValuePointOrganization {value=&msg->Organization;}

    action ValuePointPriority {value=&msg->Priority;}

    action ValuePointProxyAuthenticate {value=&msg->ProxyAuthenticate;}

    action ValuePointProxyAuthorization {value=&msg->ProxyAuthorization;}

    action ValuePointProxyRequire {value=&msg->ProxyRequire;}

    action ValuePointReferTo {value=&msg->ReferTo;}

    action ValuePointReferredBy {value=&msg->ReferredBy;}

    action ValuePointRequire {value=&msg->Require;}

    action ValuePointRetryAfter {value=&msg->RetryAfter;}

    action ValuePointServer {value=&msg->Server;}

    action ValuePointSubject {value=&msg->Subject;}

    action ValuePointSupported {value=&msg->Supported;}

    action ValuePointTimestamp {value=&msg->Timestamp;}

    action ValuePointUnsupported {value=&msg->Unsupported;}

    action ValuePointUserAgent {value=&msg->UserAgent;}

    action ValuePointWarning {value=&msg->Warning;}

    action ValuePointWWWAuthenticate {value=&msg->WWWAuthenticate;}
}%%