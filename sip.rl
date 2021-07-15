%%{# -*-ragel-*-
# Copyright 2020 Justine Alexandra Roberts Tunney
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Ragel SIP Message Parser
#
# This file is compiled into Go code by the Ragel State Machine Compiler for
# the purpose of converting SIP messages into a Msg data structure. This
# machine works in tandem with the Ragel machine defined in uri_parse.rl.
#
# The parser is deterministicly effectively O(k). It's able to parse an
# ordinary INVITE message in less than 30μs, which means 30k messages can be
# parsed per second. Best of all, messages are parsed into a very easy to use
# and transparent data structure.
#
# Perhaps it would have been better if the SIP protocol designers had chosen to
# use a binary serialization format like protocol buffers. But instead they
# chose to create a plaintext protocol that looks similar to HTTP requests, but
# are phenomenally more complicated.
#
# SIP messages are quite insane.
#
#   o Whitespace can be used liberally in a variety of different ways.
#
#     - Via host:port can have whitespace, e.g. "host \t:  port"
#
#   o UTF-8 is supported in some places but not others.
#
#   o Headers can span multiple lines.
#
#   o Header values can contain comments, e.g. Message: lol (i'm (hidden))
#
#   o Header names are case-insensitive and have shorthand notation.
#
#   o There's ~50 standard headers, many of which have custom parsing rules.
#
#   o URIs can have ;params;like=this
#
#     - Params can belong either to a URI or Addr object, e.g. <sip:uri;param>
#       cf. <sip:uri>;param
#
#     - Addresses may omit angle brackets, in which case params belong to the
#       Addr object.
#
#     - URI params ;are=escaped%20like%22this but params belonging to Addr
#       ;are="escaped like\"this"
#
#     - Backslash escaping is not like C, e.g. \t\n -> tn
#
#     - Address display name can have whitespace without quotes, which is
#       collapsed. Quoted form is not collapsed.
#
#   o Via and address headers can be repeated in two ways: repeating the
#     header, using commas within a single header, or both.
#
# See: http://www.colm.net/files/ragel/ragel-guide-6.9.pdf
# See: https://tools.ietf.org/html/rfc2234

machine sip;

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
    mark = p
}

# 字符串回溯，将p回溯到给定的游标前一个字符位置。
# 这里是 p = (mark) - 1;
action backtrack {
    fexec mark;
}

# amt 变量赋值
action start {
    amt = 0
}

# 在缓冲区中追加一个当前指针指向的字符
action append {
    buf[amt] = fc
    amt++
}

# 在缓冲区中追加一个空格
action space {
    buf[amt] = ' '
    amt++
}

# 将16进制字符数值换算成整型16进制数值并左移一位，赋值给hex变量
action hexHi {
    hex = unhex(fc) * 16
}

# 将字符类型16进制数值换算成整型16进制数值，和hex相加，并追加在buf缓冲区中
action hexLo {
    hex += unhex(fc)
    buf[amt] = hex
    amt++
}

# 将方法字符串从要解析的数据中拷贝出来
action Method {
    msg.Method = string(data[mark:p])
}

# 解析SIP大版本号
action VersionMajor {
    msg.VersionMajor = msg.VersionMajor * 10 + (fc - 0x30)
}

# 解析SIP小版本号
action VersionMinor {
    msg.VersionMinor = msg.VersionMinor * 10 + (fc - 0x30)
}

# 解析请求URI，如果请求URI解析出错，直接退出其余解析
action RequestURI {
    msg.Request, err = ParseURI(data[mark:p])
    if err != nil { return nil, err }
}

# 将状态码字符转换成10进制整数
action StatusCode {
    msg.Status = msg.Status * 10 + (int(fc) - 0x30)
}

# 提取临时缓冲区里的字符串作为Reason
action ReasonPhrase {
    msg.Phrase = string(buf[0:amt])
}

# 新建一个Via对象
action ViaNew {
    via = new(Via)
}

# viap = via->next, via = null
action Via {
    *viap = via
    viap = &via.Next
    via = nil
}

# 从输入数据中提取出via.protocol
action ViaProtocol {
    via.Protocol = string(data[mark:p])
}

# 从输入数据中提取出via.version
action ViaVersion {
    via.Version = string(data[mark:p])
}

# 提取出via.transport
action ViaTransport {
    via.Transport = string(data[mark:p])
}

# 提取出via.Host
action ViaHost {
    via.Host = string(data[mark:p])
}

# 提取出via.port
action ViaPort {
    via.Port = via.Port * 10 + (uint16(fc) - 0x30)
}

# 从缓冲区提取出via.param
action ViaParam {
    via.Param = &Param{name, string(buf[0:amt]), via.Param}
}

# 跳转到xheader状态机匹配SIP扩展头
action gxh {
    fhold;
    fgoto xheader;
}

# 从缓冲区中将字段名提取出来保存到name变量中
action name {
    name = string(data[mark:p])
}

# 把头域字段值从输入数据中提取出来
action value {{
    b := data[mark:p - 1]
    if value != nil {
        *value = string(b)
    } else {
        msg.XHeader = &XHeader{name, b, msg.XHeader}
    }
}}

#
action AddrNew {
    addr = new(Addr)
}

# 把带双引号的地址从缓冲区中提取出来
action AddrQuotedDisplay {
    addr.Display = string(buf[0:amt])
}

# 把不带双引号的地址从缓冲区中提取出来
action AddrUnquotedDisplay {{
    end := p
    for end > mark && whitespacec(data[end - 1]) {
        end--
    }
    addr.Display = string(data[mark:end])
}}

#
action AddrUri {
    addr.Uri, err = ParseURI(data[mark:p])
    if err != nil { return nil, err }
}

#
action AddrParam {
    addr.Param = &Param{name, string(buf[0:amt]), addr.Param}
}

#
action Addr {
    *addrp = addr
    addrp = &addr.Next
    addr = nil
}

#
action CallID {
    msg.CallID = string(data[mark:p])
}

#
action ContentLength {
    clen = clen * 10 + (int(fc) - 0x30)
}

#
action ContentType {
    ctype = string(data[mark:p])
}

#
action CSeq {
    msg.CSeq = msg.CSeq * 10 + (int(fc) - 0x30)
}

#
action CSeqMethod {
    msg.CSeqMethod = string(data[mark:p])
}

#
action Expires {
    msg.Expires = msg.Expires * 10 + (int(fc) - 0x30)
}

#
action MaxForwards {
    msg.MaxForwards = msg.MaxForwards * 10 + (int(fc) - 0x30)
}

#
action MinExpires {
    msg.MinExpires = msg.MinExpires * 10 + (int(fc) - 0x30)
}

# 跳转到指定的状态机表达式中开始匹配
action goto_addr { fgoto addr; }
action goto_addr_angled { fgoto addr_angled; }
action goto_addr_param { fgoto addr_param; }
action goto_addr_uri { fgoto addr_uri; }
action goto_ctype { fgoto ctype; }
action goto_header { fgoto header; }
action goto_value { fgoto value; }
action goto_via { fgoto via; }
action goto_via_param { fgoto via_param; }

# p + 2 < pe && (data[p+2] == ' ' || data[p+2] == '\t')
action lookAheadWSP { lookAheadWSP(data, p, pe) }

# 匹配空格
SP              = " ";
# 匹配tab键
HTAB            = "\t";
# 匹配回车符
CR              = "\r";
# 匹配换行符号
LF              = "\n";
# 匹配\"
DQUOTE          = "\"";
# 只有当\r\n后面跟着的字符不是SP和HTAB，才算一个有效的换行回车，否则不是
CRLF            = ( CR when !lookAheadWSP ) LF;
# 空白符
WSP             = SP | HTAB;
# 匹配回车换行符后有空格和TAB的情况
LWS             = ( WSP* ( CR when lookAheadWSP ) LF )? WSP+;
# 匹配0次到N次的LWS的情况
SWS             = LWS?;

# 碰到字段多行折叠输入的时候，折叠输入的值信息，可以用下面两个表达式得到
LWSCRLF_append  = ( CR when lookAheadWSP ) @append LF @append;
LWS_append      = ( WSP* @append LWSCRLF_append )? WSP+ @append;

# UTF-8编码数据匹配
UTF8_CONT       = 0x80..0xBF @append;
UTF8_NONASCII   = 0xC0..0xDF @append UTF8_CONT {1}
                | 0xE0..0xEF @append UTF8_CONT {2}
                | 0xF0..0xF7 @append UTF8_CONT {3}
                | 0xF8..0xFb @append UTF8_CONT {4}
                | 0xFC..0xFD @append UTF8_CONT {5};
UTF8            = 0x21..0x7F @append | UTF8_NONASCII;
# mUTF-8编码数据匹配
mUTF8_CONT      = 0x80..0xBF;
mUTF8_NONASCII  = 0xC0..0xDF mUTF8_CONT {1}
                | 0xE0..0xEF mUTF8_CONT {2}
                | 0xF0..0xF7 mUTF8_CONT {3}
                | 0xF8..0xFb mUTF8_CONT {4}
                | 0xFC..0xFD mUTF8_CONT {5};
mUTF8           = 0x21..0x7F | mUTF8_NONASCII;

# https://tools.ietf.org/html/rfc3261#section-25.1
# 下面的定义参照RFC3261文档25.1章节，定义了
reserved        = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | "," ;
mark            = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")" ;
unreserved      = alnum | mark ;
tokenc          = alnum | "-" | "." | "!" | "%" | "*" | "_" | "+" | "`"
                | "'" | "~" ;
separators      = "("  | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\\"
                | "\"" | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP
                | HTAB ;
wordc           = alnum | "-" | "." | "!" | "%" | "*" | "_" | "+" | "`"
                | "'" | "~" | "(" | ")" | "<" | ">" | ":" | "\\" | "\""
                | "/" | "[" | "]" | "?" | "{" | "}" ;
schmchars       = alnum | "+" | "-" | "." ;
word            = wordc+;
STAR            = SWS "*" SWS;
SLASH           = SWS "/" SWS;
EQUAL           = SWS "=" SWS;
LPAREN          = SWS "(" SWS;
RPAREN          = SWS ")" SWS;
RAQUOT          = ">" SWS;
LAQUOT          = SWS "<";
COMMA           = SWS "," SWS;
SEMI            = SWS ";" SWS;
COLON           = SWS ":" SWS;
HCOLON          = WSP* ":" SWS;
LDQUOT          = SWS "\"";
RDQUOT          = "\"" SWS;
escaped         = "%" ( xdigit @hexHi ) ( xdigit @hexLo ) ;
ipv4c           = digit | "." ;
ipv6c           = xdigit | "." | ":" ;
hostc           = alnum | "-" | "." ;
token           = tokenc+;
tokenhost       = ( tokenc | "[" | "]" | ":" )+;
reasonc         = UTF8_NONASCII | ( reserved | unreserved | SP | HTAB ) @append;
reasonmc        = escaped | reasonc;
cid             = word ( "@" word )?;
hval            = ( mUTF8 | LWS )* >mark;

schemec         = alnum | "+" | "-" | ".";
scheme          = alpha schemec*;
uric            = reserved | unreserved | "%" | "[" | "]";
uri             = scheme ":" uric+;

# Quoted strings can have just about anything, including backslash escapes,
# which aren't quite as fancy as the ones you'd see in programming.
# 带双引号的字符串，可能包含任何数据，包括反斜杠和转移，ESC等
qdtextc         = 0x21 | 0x23..0x5B | 0x5D..0x7E; # 匹配单个有效的字符
qdtext          = UTF8_NONASCII | LWS_append | qdtextc @append; # 匹配多个有效字符组成的字符串
quoted_pair     = "\\" ( 0x00..0x09 | 0x0B..0x0C | 0x0E..0x7F ) @append;
quoted_content  = ( qdtext | quoted_pair )* >start;
quoted_string   = DQUOTE quoted_content DQUOTE; # 带双引号的字符串匹配
unquoted_string = ( token LWS )+; # 不带双引号的字符串匹配

# Content Type Parsing
# 媒体内容解析，比较简单，只解析这种格式的数据 Content-Type = xxx/xxx;xxx=xxx;xxx="xxx",
# 其中字段和值，分隔符之间可以插入任意的空格和tab键
# This is easy-peasy. It almost always contains the value "application/sdp".
# We're going to ignore the parameters, because this information is actually
# stored in Msg by way of type interface and we don't support any types that
# take parameters.
# 解析参数Content-Type字段可能携带的参数，即同一行中;分隔符后面带的东西，即*( \t);*( \t) xxx*( \t)=*( \t)(")xxx(")
ctype_param     = SEMI token EQUAL ( token | quoted_string );
# 解析主要值，就是解析application/sdp这个字符串
ctype_mime      = ( token "/" token ) >mark %ContentType;
ctype          := ctype_mime ctype_param* CRLF @goto_header;

# Parameter Parsing
# 参数表达式匹配，可以用于匹配via和address字段的值，但是不能用于匹配URI，参数表达式类似=xxx或者="xxx"，=xxx是可选的
# Parameters can be used by vias and addresses, but not URIs. They can look
# like=this or like="this". The =value part is optional.
param_name      = token >mark %name;
param_content   = tokenhost @append;
param_value     = param_content | quoted_string;
param           = param_name >start (EQUAL param_value)?; # 后面的=xxx是可选的

# Via Parsing
# Via头字段的解析，Via头字段是用于追踪SIP的跳点，他有比较简单的语法，类似下面的例子
# Vias are used to trace SIP hops. It's similar to an address, but with simpler
# syntax. Here's some examples:
#
#   - Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK-d1d81e94a099
#   - Via: SIP/2.0/TLS [feed:a::bee] ;branch="z9hG4bK-doge" ;rport=666
#
# Parsing these is kind of difficult because infinite whitespace is allowed
# between colons, semicolons, commas, and don't forget that lines can
# continue. So we're going to break things down into four separate machines
# that jump between each other.
# 解析这些有点困难，因为冒号，分号，逗号之间允许无限的空白，不要忘记行可以继续。
# 所以我们要把事情分解成四个独立的机器，它们在彼此之间跳跃。
ViaProtocol     = token >mark %ViaProtocol;
ViaVersion      = token >mark %ViaVersion;
ViaTransport    = token >mark %ViaTransport;
# 解析 SIP/2.0/UDP 这部分字符串
ViaSent         = ViaProtocol SLASH ViaVersion SLASH ViaTransport;
ViaHostIPv4     = ipv4c+ >mark %ViaHost;
ViaHostIPv6     = "[" ipv6c+ >mark %ViaHost "]";
ViaHostName     = hostc+ >mark %ViaHost;
# 解析下一条SIP的地址，格式可以是ipv4、ipv6、域名
ViaHost         = ViaHostIPv4 | ViaHostIPv6 | ViaHostName;
# 解析端口信息
ViaPort         = digit+ @ViaPort;
via_param_end   = CRLF @ViaParam @Via @goto_header
                | SEMI <: any @ViaParam @hold @start @goto_via_param
                | COMMA <: any @ViaParam @Via @ViaNew @hold @goto_via;
# 解析via头所携带的参数，左连接保护符
via_param      := param via_param_end;
via_end         = CRLF @Via @goto_header
                | SEMI <: any @hold @start @goto_via_param
                | COMMA <: any @Via @ViaNew @hold @goto_via;
via            := ViaSent LWS ViaHost (COLON ViaPort)? via_end;

# Address Parsing
#
# These can come in the following forms, which can be comma-delimited:
#
#   - Unangled: sip:example.lol;param
#   - Angled: <sip:example.lol;param>;param
#   - Unquoted: oh my goth <sip:boo@lol[feed:a::bee]:5060>
#   - Quoted: "oh my \"goth\"" <sip:example.lol>
#
# In order to tell the unangled and unquoted angled forms apart, we need to
# look for ':' or '<' character and then backtrack to the appropriate machine.
#
# Because Addr and URI can both have parameters, one might wonder what happens
# to them in the unmangled form. Are they owned by URI? Or are they owned by
# Addr? The answer is the latter.
#
# The URIs themselves are parsed by a separate routine. All we do here is
# extract the bytes and pass them along. It would be nice if we could put the
# URI parsing in this file, where the URI parsing is invoked by fcall. But
# that's not possible, because it appears Ragel Go is broken in that regard.
addr_spec          = LAQUOT uri >mark %AddrUri RAQUOT;
addr_display       = quoted_string >start %AddrQuotedDisplay
                   | unquoted_string >mark %AddrUnquotedDisplay;
addr_param_end     = CRLF @AddrParam @Addr @goto_header
                   | SEMI <: any @AddrParam @hold @goto_addr_param
                   | COMMA <: any @AddrParam @Addr @hold @goto_addr;
addr_param        := param addr_param_end;
addr_angled_end    = CRLF @Addr @goto_header
                   | SEMI <: any @hold @goto_addr_param
                   | COMMA <: any @Addr @hold @goto_addr;
addr_angled       := addr_display? addr_spec addr_angled_end;
addr_uri_end       = CRLF %Addr @goto_header
                   | SEMI <: any @hold @goto_addr_param
                   | COMMA <: any @Addr @hold @goto_addr;
addr_uri          := ( uri - ";" ) %AddrUri addr_uri_end;
addr              := [<\"] @AddrNew @hold @goto_addr_angled
                   | unquoted_string >mark "<" @AddrNew @backtrack @goto_addr_angled
                   | scheme >mark ":" @AddrNew @backtrack @goto_addr_uri;

# Address Header Name Definitions
# 匹配到相应的带IP地址的头域字段（不区分大小写、接受缩写）时，addrp的指针指向SIP消息结构体里相应的字段的值变量，好在后续匹配成功后，直接将值拷贝到SIP消息结构体中
# These headers set the addr pointer to tell the 'value' machine where to
# store the value after using ParseAddrBytes().
aname    = ("Contact"i | "m"i) %{addrp=lastAddr(&msg.Contact)}
         | ("From"i | "f"i) %{addrp=lastAddr(&msg.From)}
         | "P-Asserted-Identity"i %{addrp=lastAddr(&msg.PAssertedIdentity)}
         | "Record-Route"i %{addrp=lastAddr(&msg.RecordRoute)}
         | "Remote-Party-ID"i %{addrp=lastAddr(&msg.RemotePartyID)}
         | "Route"i %{addrp=lastAddr(&msg.Route)}
         | ("To"i | "t"i) %{addrp=lastAddr(&msg.To)}
         ;

# String Header Name Definitions
# 匹配到相应的值是字符串的头域字段（不区分大小写、接受缩写）时，value指针指向SIP消息结构体里相应的字段的值变量，好在后续匹配成功后，直接将值拷贝到SIP消息结构体中。
# These headers set the value pointer to tell the 'value' machine where to
# store the resulting token string.
sname    = "Accept"i %{value=&msg.Accept}
         | ("Accept-Contact"i | "a"i) %{value=&msg.AcceptContact}
         | "Accept-Encoding"i %{value=&msg.AcceptEncoding}
         | "Accept-Language"i %{value=&msg.AcceptLanguage}
         | ("Allow"i | "u"i) %{value=&msg.Allow}
         | ("Allow-Events"i | "u"i) %{value=&msg.AllowEvents}
         | "Alert-Info"i %{value=&msg.AlertInfo}
         | "Authentication-Info"i %{value=&msg.AuthenticationInfo}
         | "Authorization"i %{value=&msg.Authorization}
         | "Content-Disposition"i %{value=&msg.ContentDisposition}
         | "Content-Language"i %{value=&msg.ContentLanguage}
         | ("Content-Encoding"i | "e"i) %{value=&msg.ContentEncoding}
         | "Call-Info"i %{value=&msg.CallInfo}
         | "Date"i %{value=&msg.Date}
         | "Error-Info"i %{value=&msg.ErrorInfo}
         | ("Event"i | "o"i) %{value=&msg.Event}
         | "In-Reply-To"i %{value=&msg.InReplyTo}
         | "Reply-To"i %{value=&msg.ReplyTo}
         | "MIME-Version"i %{value=&msg.MIMEVersion}
         | "Organization"i %{value=&msg.Organization}
         | "Priority"i %{value=&msg.Priority}
         | "Proxy-Authenticate"i %{value=&msg.ProxyAuthenticate}
         | "Proxy-Authorization"i %{value=&msg.ProxyAuthorization}
         | "Proxy-Require"i %{value=&msg.ProxyRequire}
         | ("Refer-To"i | "r"i) %{value=&msg.ReferTo}
         | ("Referred-By"i | "b"i) %{value=&msg.ReferredBy}
         | "Require"i %{value=&msg.Require}
         | "Retry-After"i %{value=&msg.RetryAfter}
         | "Server"i %{value=&msg.Server}
         | ("Subject"i | "s"i) %{value=&msg.Subject}
         | ("Supported"i | "k"i) %{value=&msg.Supported}
         | "Timestamp"i %{value=&msg.Timestamp}
         | "Unsupported"i %{value=&msg.Unsupported}
         | "User-Agent"i %{value=&msg.UserAgent}
         | "Warning"i %{value=&msg.Warning}
         | "WWW-Authenticate"i %{value=&msg.WWWAuthenticate}
         ;

# Custom Header Definitions
# 这些特殊的头域字段值的解析，不会用到临时变量addrp变量和value变量，而是直接定义了他们各自值的提取方法。
# These headers do not jump to the 'value' machine, but instead specify
# their own special type of parsing.
cheader  = ("Call-ID"i | "i"i) $!gxh HCOLON cid >mark %CallID
         | ("Content-Length"i | "l"i) $!gxh HCOLON digit+ >{clen=0} @ContentLength
         | "CSeq"i $!gxh HCOLON (digit+ @CSeq) LWS token >mark %CSeqMethod
         | ("Expires"i | "l"i) $!gxh HCOLON digit+ >{msg.Expires=0} @Expires
         | ("Max-Forwards"i | "l"i) $!gxh HCOLON digit+ >{msg.MaxForwards=0} @MaxForwards
         | ("Min-Expires"i | "l"i) $!gxh HCOLON digit+ >{msg.MinExpires=0} @MinExpires
         ;

# Header Parsing SIP消息头解析
#
# The header machine parses a single header and then jumps to itself to
# loop. When the final CRLF is observed, we then break out of the Ragel
# parser and let the Go code handle payload extraction.
# header状态机解析一个单个SIP消息头同时跳转到他们自己的循环中，当状态机收到CRLF时，
# 会跳出状态机，让Go代码来处理有效载荷的提取工作。
#
# Parsing standard header names is a prefix trie search in generated code.
# Lookahead to set the mark on the header name. In order to support
# extended headers, we'll use $!gxh to jump to the xheader machine when an
# unrecognized character is detected in the header name.
# 在生成的代码中，使用前缀匹配的方式处理标准的头域字段。在头域字段设置mark标记。
# 为了支持扩展头域字段，当在头域名称列表解析时遇到未知无法解析的字符时，我们使用!gxh动作来跳转到xheader状态机。
#
# An independent machine has been created for generic header values, so
# that it doesn't need to be duplicated for each leaf in the prefix
# trie. When the value machine has finished reading a value, it'll be
# parsed and stored based on whether the value/addr pointers are set.
# 已经为通用的头域字段创建了一个独立的状态机，因此不需要为了每个头域前缀去重复啥？？？
# 当value状态机结束并读取到了值，他根据是否设置了value/addr指针来解析和存储。
#
# Header values can span multiple lines. Lookahead is used in the LWS
# definition to check for whitespace at the start of the next line upon
# encountering a line feed character, in order to determine if a line
# continuation is present.
# 标题值可以跨越多行。
# Lws定义中使用前瞻，在遇到换行符时检查下一行开始处的空白，以确定是否存在行延续。
#
# In order to concatenate across machines, we use lookahead in conjunction
# with the left-guarded concatenation operator. This pattern works is
# defined as follows: `foo <: any @hold @goto_bar`.
# 为了跨机器连接，我们将前瞻与左侧保护的连接运算符结合使用。 此模式的工作原理定义如下：
# 'foo<:any@hold@goto_bar'。
#
# Header names are case insensitive. Each recognized header is assigned to
# a specific field in the Msg data structure. Extended headers are stored
# to a linked list data structure with the casing preserved. This is so
# messages can be reproduced with roughly the same appearance. It is the
# responsibility of the person using Msg.Headers to do case-insensitive
# string comparisons.
# 标题名称不区分大小写。 每个识别的报头被分配给Msg数据结构中的特定字段。
# 扩展头存储到链表数据结构中，并保留大小写。
# 这是这样的消息可以再现大致相同的外观。 使用`Msg.Headers`的人有责任进行不区分大小写的字符串比较。
value   := hval <: CRLF @value @goto_header;
xheader := token %name HCOLON <: any @{value=nil} @hold @goto_value;
sheader  = cheader <: CRLF @goto_header
         | aname $!gxh HCOLON <: any @{value=nil} @hold @goto_addr
         | sname $!gxh HCOLON <: any @hold @goto_value
         | ("Via"i | "v"i) $!gxh HCOLON <: any @ViaNew @hold @goto_via
         | ("Content-Type"i | "c"i) $!gxh HCOLON <: any @hold @goto_ctype;
header  := CRLF @break
         | tokenc @mark @hold sheader;

# Start Line Parsing SIP消息的起始行解析状态机
#
# The Request and Response definitions are very straightforward, and the
# main machine is the union of the two. Once the line feed character has
# been observed, we then jump to the header machine.
# SIP Message Parsing
# 请求和响应的定义非常简洁，主状态机是一个联合体，要么匹配解析请求消息，要么解析响应消息，
# 一旦匹配到了回车换行符，就会跳转到头域状态机，解析所有头域信息
# 解析起始行的方法名
Method          = token >mark %Method;
# 解析起始行的SIP版本信息
SIPVersionNo    = digit+ @VersionMajor "." digit+ @VersionMinor;
# 解析起始行的请求URI
RequestURI      = ^SP+ >mark %RequestURI;
# 解析起始行的状态码
StatusCode      = ( digit @StatusCode ) {3};
# 解析起始行的状态码简短描述
ReasonPhrase    = reasonmc+ >start %ReasonPhrase;
# 解析起始行的SIP版本
SIPVersion      = "SIP/" SIPVersionNo;
# 请求消息的起始行表达式，起始行匹配无误后，跳转到头域进行所有头域字段的解析
Request         = Method SP RequestURI SP SIPVersion CRLF @goto_header;
# 响应消息的起始行表达式，起始行匹配无误后，跳转到头域进行所有头域字段的解析
Response        = SIPVersion SP StatusCode SP ReasonPhrase CRLF @goto_header;
# 匹配判断SIP消息是请求消息还是响应消息
Message         = Request | Response;

}%%