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
    char *tmp = (char*) malloc(1024);
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
    msg = ParseMsg(torture2, 642, &checkLen, tmp);
    if (msg) {
        printf("SIP msg parse success, total %d bytes, check %d bytes.\n", 642, checkLen);
    }
    else {
        printf("SIP msg parse fail, total %d bytes, check %d bytes.\n", 642, checkLen);
    }
    char test[][10240] {

            "\r\n\t\t\r\t \r \t\r\n\t \n \t \r\n SIP/2.0 200 OK\r\n"
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

            "REGISTER sip:43070000002000000002@192.168.27.56:5666;transport=tcp SIP/2.0\r\n"
            "Call-ID: c2d21be17bb3fea723c142986a620008@192.168.27.98\r\n"
            "CSeq: 103 REGISTER\r\n"
            "From: <sip:34010000002000000101@192.168.27.56:20007>;tag=1616405761965\r\n"
            "To: <sip:34010000002000000101@192.168.27.95:15566>\r\n"
            "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport\r\n"
            "Max-Forwards: 70\r\n"
            "User-Agent: sip\r\n"
            "Contact: <sip:43070000002000000001@192.168.27.56:20007>\r\n"
            "OutputPort: 20007\r\n"
//            "Proxy: 192.168.26.132:15566/TCP\r\n"
            "Expires: 3600\r\n"
            "Content-Length: 0\r\n"
            "\r\n",

            "SIP/2.0 200 OK\r\n"
            "CSeq: 25 MESSAGE\r\n"
            "Call-ID: 09961f85f3e167f0f670f303c687efaf@192.168.27.41\r\n"
            "From: <sip:43070000002000000001@192.168.27.41:15566>;tag=1617269100606\r\n"
            "To: <sip:34010000002000000101@192.168.27.95:20000>;tag=1617269133086\r\n"
            "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport=5666;received=192.168.27.56\r\n"
            "User-Agent: sip\r\n"
//            "Proxy: 192.168.26.132:15566/TCP\r\n"
            "Contact: <sip:34010000002000000101@192.168.27.56:20008>\r\n"
            "Content-Length: 0\r\n"
            "\r\n",

            "SIP/2.0 200 OK\r\n"
            "CSeq: 25 MESSAGE\r\n"
            "Call-ID: 09961f85f3e167f0f670f303c687efaf@192.168.27.41\r\n"
            "From: <sip:43070000002000000001@192.168.27.41:15566>;tag=1617269100606\r\n"
            "To: <sip:34010000002000000101@192.168.27.95:20000>;tag=1617269133086\r\n"
            "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport=5666;received=192.168.27.56\r\n"
            "User-Agent: sip\r\n"
//            "Proxy: 192.168.26.132:15566/TCP\r\n"
            "Contact: <sip:34010000002000000101@192.168.27.56:20008>\r\n"
            "Content-Length: 0\r\n"
            "\r\n",

            "MESSAGE sip:43070000002000000001@192.168.27.95:15566 SIP/2.0\r\n"
            "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport\r\n"
            "From: <sip:34010000002000000101@192.168.27.56:20008>;tag=1617270900004\r\n"
            "To: <sip:43070000002000000001@192.168.27.95:15566>\r\n"
            "Call-ID: 2f981c77d0cecd01804742a0ed21fd17@192.168.27.98\r\n"
            "CSeq: 2245 MESSAGE\r\n"
            "Max-Forwards: 70\r\n"
            "Content-Type: application/MANSCDP+xml\r\n"
            "User-Agent: sip\r\n"
            "OutputPort: 20007\r\n"
//            "Proxy: 192.168.26.132:15566/TCP\r\n"
            "Content-Length: 187\r\n"
            "\r\n"
            "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"
            "<Notify>\r\n"
            "    <CmdType>Keepalive</CmdType>\r\n"
            "    <SN>117</SN>\r\n"
            "    <DeviceID>340110000002000000101</DeviceID>\r\n"
            "    <Status>OK</Status>\r\n"
            "</Notify>\r\n",

            "REGISTER sip:35000000002000000000@183.252.194.84:15566 SIP/2.0\r\n"
            "Via: SIP/2.0/TCP 192.168.1.215:5060;rport;branch=z9hG4bK1471116192\r\n"
            "From: <sip:35010201081320000127@192.168.1.215:5060>;tag=353287808\r\n"
            "To: <sip:35010201081320000127@192.168.1.215:5060>\r\n"
            "Call-ID: f3g4h51180451287@192.168.1.215\r\n"
            "CSeq: 2 REGISTER\r\n"
            "Contact: <sip:35010201081320000127@172.21.66.5:21432>\r\n"
            "Authorization: Digest username=\"35010201081320000127\", realm=\"172.21.66.8:15566\", nonce=\"d5930231868ee573bbeb1fea43aac963\", uri=\"sip:35000000002000000000@183.252.194.84:15566\", response=\"dd9d9bc908ecec41509a8c3a09ac5408\", algorithm=MD5, cnonce=\"0a4f113b\", opaque=\"e87abfeff0d1031ba4a9c12e77177e75\", qop=auth, nc=00000001\r\n"
            "Max-Forwards: 70\r\n"
            "User-Agent: VCP MWARE\r\n"
            "Expires: 3600\r\n"
            "RegMode: DEVICE;Describe=CMCC-IPC-A35;Register;DevVer=DIPC-B1210.A31A35.86.210208\r\n"
            "ReplaceDescribe: CMCC-IPC-A35;ProductId=defaultProductId;RegionCode=DT;Vendor=CMCC;Resolve=HIC1080P;Ptzfg=0;;SnmpVer=v3\r\n"
            "Ability: UCSStore=0\r\n"
            "Content-Length: 0\r\n"
            "\r\n",

    };
    int len = sizeof(test)/10240;
    for (int i = 0; i < len; i++) {
        sipLen = strlen(test[i]);
        checkLen = 0;
        msg = ParseMsg(test[i], sipLen, &checkLen, tmp);
        if (msg) {
            printf("SIP msg parse success, total %d bytes, check %d bytes.\n", sipLen, checkLen);
        }
        else {
            printf("SIP msg parse fail, total %d bytes, check %d bytes.\n", sipLen, checkLen);
        }
    }
    free(tmp);
}

#include <sys/stat.h>
int fileSize(char *filename) {
    struct stat statbuf;
    stat(filename, &statbuf);
    int size = statbuf.st_size;
    return size;
}

#include <sys/time.h>

#define MAX_BUFF (1024*1024*1024)
void Test_File(char *filename, int count) {
    FILE *fp = 0;
    char * buf = 0, *tmp = 0;
    int pos = 0;
    Msg *msg = 0;
    int msgCount = 0;
    int p = 0;
    int rlen;
    int fSize;
    struct timeval tStart, tRun, tEnd;
    unsigned long long start = 0, end = 0;

    gettimeofday(&tStart, 0);
    start = tStart.tv_sec*1000 + tStart.tv_usec/1000;

    fp = fopen(filename, "rb");
    if (!fp) {
        printf("file [%s] open fail\n", filename);
        goto _end;
    }
    fSize = fileSize(filename);
    if (fSize > MAX_BUFF) {
        printf("file too big [%d] MByte, cannot load to memory\n", fSize/1024/1024);
        goto _end;
    }
    // 开辟缓冲区，并读取文件到缓冲区
    buf = (char*) malloc(fSize);
    memset(buf, 0, fSize);
    rlen = fread(buf, 1, fSize, fp);
    if (rlen < fSize) {
        printf("load file to memory fail, will load %d bytes, real load %d bytes.\n", fSize, rlen);
        goto _end;
    }
    gettimeofday(&tRun, 0);
    end = tRun.tv_sec*1000 + tRun.tv_usec/1000;
    printf("load file cost %llu ms\n", end - start);
    tmp = (char*) malloc(8192);

    gettimeofday(&tRun, 0);
    start = tRun.tv_sec * 1000 + tRun.tv_usec/1000;

    // 循环解析1000次sip.txt中的内容
    for (int i = 0; i < count; i++) {

        p = pos = 0;
        rlen = fSize;
        msgCount = 0;

        // 循环处理缓冲区数据
        while (rlen) {
            msg = ParseMsg(&buf[pos], 8192, &p, 0);
            if (msg) {
                msgCount++;
                if (msg->Payload) {
                    pos += msg->Payload->Data.length();
                    rlen -= msg->Payload->Data.length();
                }
                delete msg;
                msg = 0;
            }
            else {
                break;
            }
            pos += p;
            rlen -= p;
        }
    }
    gettimeofday(&tEnd, 0);
    end = tEnd.tv_sec * 1000 + tEnd.tv_usec/1000;
    printf("parse file [%d] KBytes, %d sip msg, cost %lld ms\n", fSize*count / 1024, msgCount*count, end - start);
_end:
    printf("function end\n");
    if (buf)
        free(buf);
    if (fp)
        fclose(fp);
    if (msg)
        delete msg;
    if (tmp)
        free(tmp);
    return;
}

int main(int argc, char **argv) {
    // 读取参数，参数为要解析的文件路径
    for (int i = 0 ; i < argc; i++) {
        printf("argv[%d] = %s\n", i, argv[i]);
    }
    Test_ParseUri();

    Test_ParseMsg();

    if (argc > 1) {
        int c = 1;
        if (argc > 2)
            c = atoi(argv[2]);
        if (c == 0) c = 1;
        Test_File(argv[1], c);
    }

}