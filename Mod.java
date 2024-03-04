public class Mod {
    //a^b mod n
    public long FastExpo(long a, long b, long n) {
        long result = 1;

        if (n == 0) { // mod 0
            while (b > 0) {
                if (b % 2 == 1) {
                    result *= a;
                }
                a *= a;
                b >>= 1;
            }
            return result;
        }
        else {
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
}