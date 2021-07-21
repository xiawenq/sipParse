
%%{
    machine uri_parse_core;
    # 包含具体的目标代码的动作、封装源代码定义文件
    include uri_parse_act "uri_parse_java.rl";
    # Byte character definitions.
    mark            = "-" | "_" | "." | "!" | "~" | "*" | "'" | "(" | ")";
    reserved        = ";" | "/" | "?" | ":" | "@" | "&" | "=" | "+" | "$" | ",";
    unreserved      = alnum | mark;
    ipv4c           = digit | ".";
    ipv6c           = xdigit | "." | ":";
    hostc           = alnum | "-" | ".";
    telc            = digit | "+" | "-";
    schemec         = alnum | "+" | "-" | ".";
    uric            = reserved | unreserved | "%" | "[" | "]";
    userc           = unreserved | "&" | "=" | "+" | "$" | "," | ";" | "?" | "/";
    passc           = unreserved | "&" | "=" | "+" | "$" | ",";
    paramc          = unreserved | "[" | "]" | "/" | ":" | "&" | "+" | "$";
    headerc         = unreserved | "[" | "]" | "/" | "?" | ":" | "+" | "$";

    # Multibyte character definitions.
    escaped         = "%" ( xdigit @hexHi ) ( xdigit @hexLo );
    userchar        = escaped | ( userc @append );
    passchar        = escaped | ( passc @append );
    paramchar       = escaped | ( paramc @append );
    headerchar      = escaped | ( headerc @append );

    # URI component definitions.
    scheme          = ( alpha schemec* ) >start @lower %scheme;
    user            = userchar+ >start %user;
    pass            = passchar+ >start %pass;
    host6           = "[" ( ipv6c+ >start @lower %host ) "]";
    host            = host6 | ( ( ipv4c | hostc | telc )+ >start @lower %host );
    port            = digit+ @port;
    paramkey        = paramchar+ >start >b2 %b1;
    paramval        = paramchar+ >start %b2;
    param           = ";" paramkey ( "=" paramval )? %param;
    headerkey       = headerchar+ >start >b2 %b1;
    headerval       = headerchar+ >start %b2;
    header          = headerkey ( "=" headerval )? %header;
    headers         = "?" header ( "&" header )*;
    userpass        = user ( ":" pass )?;
    hostport        = host ( ":" port )?;
    uriSansUserCore    = scheme ":" hostport param* headers?;
    uriWithUserCore    = scheme ":" userpass "@" hostport param* headers?;

    # XXX: This backtracking solution causes a weird Ragel bug.
    # uri            := any+ >mark %backtrack %goto_uriSansUser
    #                |  any+ >mark :> "@" @backtrack @goto_uriWithUser;
}%%
