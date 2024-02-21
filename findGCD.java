import java.util.concurrent.ThreadLocalRandom;

public class findGCD { 
    public GeneratePrime GP = new GeneratePrime();

    public long GCD(long a, long b) {
        return extendedGCD(a, b)[2]; 
    }

    public long[] extendedGCD(long a, long n) {
        long x0 = 1, x1 = 0;
        long y0 = 0, y1 = 1;
        
        while (n != 0) {
            long q = a / n;
            long[] result = new long[2];
            result[0] = x0 - q * x1;
            result[1] = y0 - q * y1;
            
            // Update x and y
            x0 = x1;
            x1 = result[0];
            y0 = y1;
            y1 = result[1];
            
            // Perform the division step of Euclid's Algorithm
            long temp = n;
            n = a % n;
            a = temp;
        }
        // x0 and y0 are the coefficients of a and n respectively
        return new long[]{x0, y0, a}; // Returns [x, y, GCD]
    }

    public long findInverse(long a, long n) {
        long result[] = extendedGCD(a, n);
        long gcd = result[2];
        if (gcd != 1) {
            return -1;
        } else {
            return (result[0] % n + n) % n;
        }
    }

    public long[] GenRandomNowithInverse(long n) {
        long e = ThreadLocalRandom.current().nextLong(2, n - 1);
        // Loop until a suitable 'e' is found where gcd(e, n) = 1
        while (GCD(e, n) != 1) {
            e = ThreadLocalRandom.current().nextLong(2, n - 1);
        }
        // Calculate the modular inverse of 'e' modulo 'n'
        long eInverse = findInverse(e, n);

        return new long[]{e, eInverse, n}; 
    }
}