import java.util.concurrent.ThreadLocalRandom;

public class checkPrime {
    findGCD fGCD;
    Mod mod;

    // lehmann test 
    public boolean isPrime(long n) {
        fGCD = new findGCD();
        mod = new Mod();
        
        if (n <= 1) { // 0-1
            return false;
        }
        if (n <= 3) { // 2-3
            return true;
        }

        long e = (n - 1) / 2;
        
        // Perform the test 100 times
        for (int i = 0; i < 100; i++) {
            long a = ThreadLocalRandom.current().nextLong(2, n - 1);

            if (fGCD.GCD(a, n) != 1) { 
                return false;
            }
            else {
                long result = mod.FastExpo(a, e, n);

                // If result is not 1 or n-1, n is definitely not prime
                if (result != 1 && result != n-1) {
                    return false;
                }
            }
        }
        return true;
    }
}