import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;

public class GeneratePrime {
    private checkPrime prime;
    private BigInteger nBit = BigInteger.ZERO;
    private Mod mod = new Mod();

    public BigInteger GenPrime(BigInteger n, String Filename) {
        BigInteger number = BigInteger.ZERO;
        BigInteger safePrime = BigInteger.ZERO;
        BigInteger minRangeValue = mod.FastExpo(BigInteger.TWO, n.subtract(BigInteger.ONE), BigInteger.ZERO);
        BigInteger maxRangeValue = mod.FastExpo(BigInteger.TWO, n, BigInteger.ZERO).subtract(BigInteger.ONE);
        nBit = n;


        // Validate the input n before proceeding
        if (n.compareTo(BigInteger.TWO) < 0) { // 0 - 1
            throw new IllegalArgumentException("Error: Cannot generate a prime number with less than 2 bits.");
        }
        if (n.equals(BigInteger.TWO)) { // 2
            throw new IllegalArgumentException("Error: Cannot generate a safe prime number with 2.");
        }

        prime = new checkPrime();
        StringBuilder binaryString = new StringBuilder();
        try {  
            FileInputStream fis = new FileInputStream(Filename);
            int value;
            boolean foundOne = false;
            while ((value = fis.read()) != -1 && binaryString.length() < n.intValue()) {
                for (int i = 7; i >= 0 && binaryString.length() < n.intValue(); i--) {
                    int bit = (value >> i) & 1;
                    if (bit == 1 || foundOne) {
                        binaryString.append(bit);
                        foundOne = true;
                    }
                    System.out.print(bit); // before foundOne
                }
            }
            System.out.println();
            System.out.println("binary: " +binaryString); // after foundOne
            number = new BigInteger(binaryString.toString(), 2);
            fis.close();

            if (binaryString.length() < n.intValue()) {
                throw new IOException("Not enough data to read " + n + " bits.");
            }

            if (!foundOne) {
                throw new IOException("Failed to find a starting bit of 1 in the entire file.");
            }

            // Adjust number to be within range and odd
            if (number.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
                number = number.add(BigInteger.ONE);
            }

            // Old
            // Find the prime number
            /* while (!prime.isPrime(number)) {
                number += 2; // Always add 2 to stay odd
                if (number >= (maxRangeValue)) {
                    number = minRangeValue + 1; // Wrap back to the minimum of the range and ensure it's odd
                }
            } */

            // new
            while (true) {
                safePrime = number.multiply(BigInteger.TWO).add(BigInteger.ONE); // p = p1 * 2 + 1
                if (prime.isPrime(number) && prime.isPrime(safePrime) && safePrime.compareTo(maxRangeValue) <= 0) {
                    break; // Found a valid safe prime within range
                }
                number = number.add(BigInteger.TWO);
                if (number.compareTo(maxRangeValue) > 0 || safePrime.compareTo(maxRangeValue) > 0) {
                    number = minRangeValue.divide(BigInteger.TWO).add(BigInteger.ONE);
                } 
            }
            System.out.println("num: " +number); // p1
            System.out.println("safe: " +safePrime); // p
            
        } catch (IOException e) {
            System.err.println("Error reading from file: " + e.getMessage());
        }
        // Output the found prime number
        return safePrime;
    }

    public BigInteger getnBit() {
        return nBit;
    }
}