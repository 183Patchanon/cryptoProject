import java.math.BigInteger;
import java.security.SecureRandom;

public class checkPrime {
    findGCD fGCD;
    Mod mod;

    // lehmann test 
    public boolean isPrime(BigInteger n) {
        fGCD = new findGCD();
        mod = new Mod();
        SecureRandom secureRandom = new SecureRandom();
        
        if (n.compareTo(BigInteger.ONE) <= 0) { // 0-1
            return false;
        }
        if (n.compareTo(BigInteger.valueOf(3)) <= 0) { // 2-3
            return true;
        }

        BigInteger e = n.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        
        // Perform the test 100 times
        for (int i = 0; i < 100; i++) {
            BigInteger a = new BigInteger(n.bitLength(), secureRandom).mod(n.subtract(BigInteger.TWO)).add(BigInteger.TWO);

            if (!fGCD.GCD(a, n).equals(BigInteger.ONE)) { 
                return false;
            }
            else {
                BigInteger result = mod.FastExpo(a, e, n);

                // If result is not 1 or n-1, n is definitely not prime
                if (!result.equals(BigInteger.ONE) && !result.equals(n.subtract(BigInteger.ONE))) {
                    return false;
                }
            }
        }
        return true;
    }
}