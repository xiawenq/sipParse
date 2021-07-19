//
// Created by xiawq on 2021/7/19.
//

#include "common.h"
#include <cstring>

void Test_ParseUri() {
    char test[][1024] = {
            "",
            "sip:",
            "sip:example.com:LOL",
            "sip:example.com",
            "sip:example.com:5060",
            "sips:jart@google.com",
            "sips:jart@google.com:5060",
            "sips:jart:letmein@google.com",
            "sips:jart:LetMeIn@google.com:5060",
            "sips:GOOGLE.com",
            "sip:[dead:beef::666]:5060",
            "sip:dead:beef::666:5060",
            "tel:+12126660420",
            "sip:bob%20barker:priceisright@[dead:beef::666]:5060;isup-oli=00",
            "sips:google.com ;lol ;h=omg",
            "SIP:example.com",
            "sips:alice@atlanta.com?priority=urgent&subject=project%20x",
            "sip:+1-212-555-1212:1234@gateway.com;user=phone",
            "sip:atlanta.com;method=register?to=alice%40atlanta.com",
            "sip:alice;day=tuesday@atlanta.com",
    };
    int len = sizeof(test)/ 1024;
    for (int i = 0; i < len; i++) {
        URI *uri = ParseURI(test[i], strlen(test[i]));
        if (uri) {
            printf("parse URI success\n");
            delete uri;
        }
    }
}

void Test_ParseMsg() {
    int checkLen = 0;
    int sipLen = 0;
    Msg *msg = 0;
    // 变态级别的SIP解析，带截断符的情况，只能指定字符串长度，不能用strlen
    char torture2[642] = "!interesting-Method0123456789_*+`.%indeed'~ sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*:&it+has=1,weird!*pas$wo~d_too.(doesn't-it)@example.com SIP/2.0\r\n"
                    "Via: SIP/2.0/TCP host1.example.com;branch=z9hG4bK-.!%66*_+`'~\r\n"
                    "To: \"BEL:\\\x07 NUL:\\\x00 DEL:\\\x7F\" <sip:1_unusual.URI~(to-be!sure)&isn't+it$/crazy?,/;;*@example.com>\r\n"
                    "From: token1~` token2'+_ token3*%!.- <sip:mundane@example.com>;fromParam''~+*_!.-%=\"\xD1\x80\xD0\xB0\xD0\xB1\xD0\xBE\xD1\x82\xD0\xB0\xD1\x8E\xD1\x89\xD0\xB8\xD0\xB9\";tag=_token~1'+`*%!-.\r\n"
                    "Call-ID: intmeth.word%ZK-!.*_+'@word`~)(><:\\/\"][?}{\r\n"
                    "CSeq: 139122385 !interesting-Method0123456789_*+`.%indeed'~\r\n"
                    "Max-Forwards: 255\r\n"
                    "extensionHeader-!.%*+_`'~:\xEF\xBB\xBF\xE5\xA4\xA7\xE5\x81\x9C\xE9\x9B\xBB\r\n"
                    "Content-Length: 0\r\n"
                    "\r\n";
    msg = ParseMsg(torture2, 642, &checkLen);
    if (msg) {
        printf("SIP msg parse success, total %d bytes, check %d bytes.\n", 642, checkLen);
    }
    else {
        printf("SIP msg parse fail, total %d bytes, check %d bytes.\n", 642, checkLen);
    }
    char test[][10240] {

            "SIP/2.0 200 OK\r\n"
            "Via: SIP/2.0/UDP 1.2.3.4:55345;branch=z9hG4bK-d1d81e94a099\r\n"
            "From: <sip:+12126660420@fl.gg>;tag=68e274dbd83b\r\n"
            "To: <sip:+12125650666@fl.gg>;tag=gK0cacc73a\r\n"
            "Call-ID: 042736d4-0bd9-4681-ab86-7321443ff58a\r\n"
            "CSeq: 31109 INVITE\r\n"
            "Record-Route: <sip:216.115.69.133:5060;lr>\r\n"
            "Record-Route: <sip:216.115.69.144:5060;lr>\r\n"
            "Contact: <sip:+12125650666@4.55.22.99:5060>\r\n"
            "Content-Type: application/sdp-lol\r\n"
            "Content-Length:  168\r\n"
            "\r\n"
            "v=0\r\n"
            "o=- 24294 7759 IN IP4 4.55.22.66\r\n"
            "s=-\r\n"
            "c=IN IP4 4.55.22.66\r\n"
            "t=0 0\r\n"
            "m=audio 19580 RTP/AVP 0 101\r\n"
            "a=rtpmap:101 telephone-event/8000\r\n"
            "a=fmtp:101 0-15\r\n"
            "a=maxptime:20\r\n",
    };
    int len = sizeof(test)/10240;
    for (int i = 0; i < len; i++) {
        sipLen = strlen(test[i]);
        checkLen = 0;
        msg = ParseMsg(test[i], sipLen, &checkLen);
        if (msg) {
            printf("SIP msg parse success, total %d bytes, check %d bytes.\n", sipLen, checkLen);
        }
        else {
            printf("SIP msg parse fail, total %d bytes, check %d bytes.\n", sipLen, checkLen);
        }
    }
}

int main(int argc, char **argv) {
    Test_ParseUri();

    Test_ParseMsg();
}