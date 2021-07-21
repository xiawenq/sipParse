import sip.Msg;
import sip.URI;

import java.io.*;
import java.util.Arrays;

import static sip.msg_parse.ParseMsg;
import static sip.uri_parse.ParseURI;

public class Launcher {
    static void Test_ParseUri() {
        String[] test = {
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
        for (int i = 0; i < test.length; i++) {
            byte[] data = test[i].getBytes();
            URI uri = ParseURI(data, data.length);
            if (uri != null) {
                System.out.println(test[i] + ", parse success\n" + uri.toString());
            }
        }
    }

    static void Test_ParseMsg() {
        String test[] = {

                "\r\n\t\t\r\t \r \t\r\n\t \n \t \r\n SIP/2.0 200 OK\r\n"+
                "Via: SIP/2.0/UDP 1.2.3.4:55345;branch=z9hG4bK-d1d81e94a099\r\n"+
                "Via: SIP/2.0/UDP 4567:12345;branch=z9hG4bK-d1d811233\r\n"+
                "From: <sip:+12126660420@fl.gg>;tag=68e274dbd83b\r\n"+
                "To: <sip:+12125650666@fl.gg>;tag=gK0cacc73a\r\n"+
                "Call-ID: 042736d4-0bd9-4681-ab86-7321443ff58a\r\n"+
                "CSeq: 31109 INVITE\r\n"+
                "Record-Route: <sip:216.115.69.133:5060;lr>\r\n"+
                "Record-Route: <sip:216.115.69.144:5060;lr>\r\n"+
                "Contact: <sip:+12125650666@4.55.22.99:5060>\r\n"+
                "Content-Type: application/sdp-lol\r\n"+
                "Content-Length:  168\r\n"+
                "\r\n"+
                "v=0\r\n"+
                "o=- 24294 7759 IN IP4 4.55.22.66\r\n"+
                "s=-\r\n"+
                "c=IN IP4 4.55.22.66\r\n"+
                "t=0 0\r\n"+
                "m=audio 19580 RTP/AVP 0 101\r\n"+
                "a=rtpmap:101 telephone-event/8000\r\n"+
                "a=fmtp:101 0-15\r\n"+
                "a=maxptime:20\r\n",

                "REGISTER sip:43070000002000000002@192.168.27.56:5666;transport=tcp SIP/2.0\r\n"+
                "Call-ID: c2d21be17bb3fea723c142986a620008@192.168.27.98\r\n"+
                "CSeq: 103 REGISTER\r\n"+
                "From: <sip:34010000002000000101@192.168.27.56:20007>;tag=1616405761965\r\n"+
                "To: <sip:34010000002000000101@192.168.27.95:15566>\r\n"+
                "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport\r\n"+
                "Max-Forwards: 70\r\n"+
                "User-Agent: sip\r\n"+
                "Contact: <sip:43070000002000000001@192.168.27.56:20007>\r\n"+
                "OutputPort: 20007\r\n"+
//            "Proxy: 192.168.26.132:15566/TCP\r\n"+
                "Expires: 3600\r\n"+
                "Content-Length: 0\r\n"+
                "\r\n",

                "SIP/2.0 200 OK\r\n"+
                "CSeq: 25 MESSAGE\r\n"+
                "Call-ID: 09961f85f3e167f0f670f303c687efaf@192.168.27.41\r\n"+
                "From: <sip:43070000002000000001@192.168.27.41:15566>;tag=1617269100606\r\n"+
                "To: <sip:34010000002000000101@192.168.27.95:20000>;tag=1617269133086\r\n"+
                "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport=5666;received=192.168.27.56\r\n"+
                "User-Agent: sip\r\n"+
//            "Proxy: 192.168.26.132:15566/TCP\r\n"+
                "Contact: <sip:34010000002000000101@192.168.27.56:20008>\r\n"+
                "Content-Length: 0\r\n"+
                "\r\n",

                "SIP/2.0 200 OK\r\n"+
                "CSeq: 25 MESSAGE\r\n"+
                "Call-ID: 09961f85f3e167f0f670f303c687efaf@192.168.27.41\r\n"+
                "From: <sip:43070000002000000001@192.168.27.41:15566>;tag=1617269100606\r\n"+
                "To: <sip:34010000002000000101@192.168.27.95:20000>;tag=1617269133086\r\n"+
                "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport=5666;received=192.168.27.56\r\n"+
                "User-Agent: sip\r\n"+
//            "Proxy: 192.168.26.132:15566/TCP\r\n"+
                "Contact: <sip:34010000002000000101@192.168.27.56:20008>\r\n"+
                "Content-Length: 0\r\n"+
                "\r\n",

                "MESSAGE sip:43070000002000000001@192.168.27.95:15566 SIP/2.0\r\n"+
                "Via: SIP/2.0/TCP 192.168.26.132:5070;branch=z9hG4bK1616405761965-c2d21be17bb3fea723c142986a620008-192.168.26.132-60903-register383939-192.168.26.132-15566;rport\r\n"+
                "From: <sip:34010000002000000101@192.168.27.56:20008>;tag=1617270900004\r\n"+
                "To: <sip:43070000002000000001@192.168.27.95:15566>\r\n"+
                "Call-ID: 2f981c77d0cecd01804742a0ed21fd17@192.168.27.98\r\n"+
                "CSeq: 2245 MESSAGE\r\n"+
                "Max-Forwards: 70\r\n"+
                "Content-Type: application/MANSCDP+xml\r\n"+
                "User-Agent: sip\r\n"+
                "OutputPort: 20007\r\n"+
//            "Proxy: 192.168.26.132:15566/TCP\r\n"+
                "Content-Length: 187\r\n"+
                "\r\n"+
                "<?xml version=\"1.0\" encoding=\"GB2312\"?>\r\n"+
                "<Notify>\r\n"+
                "    <CmdType>Keepalive</CmdType>\r\n"+
                "    <SN>117</SN>\r\n"+
                "    <DeviceID>340110000002000000101</DeviceID>\r\n"+
                "    <Status>OK</Status>\r\n"+
                "</Notify>\r\n",

                "REGISTER sip:35000000002000000000@183.252.194.84:15566 SIP/2.0\r\n"+
                "Via: SIP/2.0/TCP 192.168.1.215:5060;rport;branch=z9hG4bK1471116192\r\n"+
                "From: <sip:35010201081320000127@192.168.1.215:5060>;tag=353287808\r\n"+
                "To: <sip:35010201081320000127@192.168.1.215:5060>\r\n"+
                "Call-ID: f3g4h51180451287@192.168.1.215\r\n"+
                "CSeq: 2 REGISTER\r\n"+
                "Contact: <sip:35010201081320000127@172.21.66.5:21432>\r\n"+
                "Authorization: Digest username=\"35010201081320000127\", realm=\"172.21.66.8:15566\", nonce=\"d5930231868ee573bbeb1fea43aac963\", uri=\"sip:35000000002000000000@183.252.194.84:15566\", response=\"dd9d9bc908ecec41509a8c3a09ac5408\", algorithm=MD5, cnonce=\"0a4f113b\", opaque=\"e87abfeff0d1031ba4a9c12e77177e75\", qop=auth, nc=00000001\r\n"+
                "Max-Forwards: 70\r\n"+
                "User-Agent: VCP MWARE\r\n"+
                "Expires: 3600\r\n"+
                "RegMode: DEVICE;Describe=CMCC-IPC-A35;Register;DevVer=DIPC-B1210.A31A35.86.210208\r\n"+
                "ReplaceDescribe: CMCC-IPC-A35;ProductId=defaultProductId;RegionCode=DT;Vendor=CMCC;Resolve=HIC1080P;Ptzfg=0;;SnmpVer=v3\r\n"+
                "Ability: UCSStore=0\r\n"+
                "Content-Length: 0\r\n"+
                "\r\n",
        };
        for (String s : test) {
            Integer checkLen = 0;
            Msg msg = ParseMsg(s.getBytes(), s.length(), checkLen);
            if (msg != null) {
                System.out.println("SIP msg parse success, total " + s.length() + ", check " + checkLen + " bytes.");
                System.out.println(msg.toString());
            }
            else {
                System.out.println("SIP msg parse fail, total " + s.length() + ", check " + checkLen + " bytes.");
            }
        }
    }

    static void Test_File(String filename, int count) throws IOException {
        File file = new File(filename);
        if (file.isFile() && file.exists()) {
            System.out.println(filename + "大小 " + file.length()/1024 + " KBytes");
            InputStream in = new FileInputStream(file);
            byte []tempbytes = new byte[512];
            int byteRead = 0;
            while ((byteRead = in.read(tempbytes)) != -1) {
                System.out.write(tempbytes, 0, byteRead);
            }

        }
        else {
            System.out.println("该文件不存在");
        }
    }

    public static void main(String[] args) {
        System.out.println("hello this is java version, 当前路径:" + System.getProperty("user.dir"));

//        Test_ParseUri();

        Test_ParseMsg();

        if (args.length > 0) {
            try {
                Test_File(args[0], 1);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
