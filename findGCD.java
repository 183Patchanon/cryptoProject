import java.security.SecureRandom;
import java.math.BigInteger;

public class findGCD { 
    public GeneratePrime GP = new GeneratePrime();
    private SecureRandom secureRandom = new SecureRandom();

    public BigInteger GCD(BigInteger a, BigInteger b) {
        return extendedGCD(a, b)[2]; 
    }

    public BigInteger[] extendedGCD(BigInteger a, BigInteger n) {
        BigInteger x0 = BigInteger.ONE, x1 = BigInteger.ZERO;
        BigInteger y0 = BigInteger.ZERO, y1 = BigInteger.ONE;
        
        while (!n.equals(BigInteger.ZERO)) {
            BigInteger q = a.divide(n);
            BigInteger[] result = new BigInteger[2];
            result[0] = x0.subtract(q.multiply(x1));
            result[1] = y0.subtract(q.multiply(y1));
            
            // Update x and y
            x0 = x1;
            x1 = result[0];
            y0 = y1;
            y1 = result[1];
            
            // Perform the division step of Euclid's Algorithm
            BigInteger temp = n;
            n = a.mod(n);
            a = temp;
        }
        // x0 and y0 are the coefficients of a and n respectively
        return new BigInteger[]{x0, y0, a}; // Returns [x, y, GCD]
    }

    public BigInteger findInverse(BigInteger a, BigInteger n) {
        BigInteger[] result = extendedGCD(a, n);
        BigInteger gcd = result[2];
        if (!gcd.equals(BigInteger.ONE)) {
            return BigInteger.valueOf(-1);
        } else {
            return (result[0].mod(n).add(n)).mod(n); // +n if mod(x0) < 0
        }
    }

    public BigInteger[] GenRandomNowithInverse(BigInteger n) {
        // random [2, n-1]
        BigInteger e = new BigInteger(n.bitLength(), secureRandom).mod(n.subtract(BigInteger.TWO)).add(BigInteger.TWO);
        // Loop until a suitable 'e' is found where gcd(e, n) = 1
        while (!GCD(e, n).equals(BigInteger.ONE)) {
            e = new BigInteger(n.bitLength(), secureRandom).mod(n.subtract(BigInteger.TWO)).add(BigInteger.TWO);
        }
        // Calculate the modular inverse of 'e' modulo 'n'
        BigInteger eInverse = findInverse(e, n);

        return new BigInteger[]{e, eInverse, n}; 
    }
}