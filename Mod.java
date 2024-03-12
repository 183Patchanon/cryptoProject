import java.math.BigInteger;

public class Mod {
    // a^b mod n
    public BigInteger FastExpo(BigInteger a, BigInteger b, BigInteger n) {
        BigInteger result = BigInteger.ONE;

        if (n.equals(BigInteger.ZERO)) { // mod 0
            while (b.compareTo(BigInteger.ZERO) > 0) {
                if (b.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                    result = result.multiply(a);
                }
                a = a.multiply(a);
                b = b.shiftRight(1);
            }
        } else {
            a = a.mod(n);
            while (b.compareTo(BigInteger.ZERO) > 0) {
                if (b.mod(BigInteger.TWO).equals(BigInteger.ONE)) {
                    result = result.multiply(a).mod(n);
                }
                b = b.shiftRight(1);
                a = a.multiply(a).mod(n);
            }
        }
        return result;
    }
}