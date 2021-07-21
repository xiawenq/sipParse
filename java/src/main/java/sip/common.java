package sip;

public class common {
    public static byte unhex(byte b) {
        if ('0' <= b && b <= '9')
            return (byte) (b - '0');
        if ('a' <= b && b <= 'f')
            return (byte) (b - 'a' + 10);
        if ('A' <= b && b <= 'F')
            return (byte) (b - 'A' + 10);
        return 0;
    }

    public static boolean lookAheadWSP(byte []data, int p, int pe) {
        return p+2 < pe && (data[p+2] == ' ' || data[p+2] == '\t');
    }

    public static boolean whitespace(byte c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n';
    }

    public static Addr lastAddr(Addr addrp) {
        if (addrp.Next != null)
            return lastAddr(addrp.Next);
        else
            return addrp;
    }
}
