public class Mod {
    //a^b mod n
    public long FastExpo(long a, long b, long n) {
        long result = 1;
        a %= n;
        while (b > 0) {
            if (b % 2 == 1) {
                result = (result * a) % n;
            }
            b = b >> 1;
            a = (a * a) % n;
        }
        return result;
    }
}