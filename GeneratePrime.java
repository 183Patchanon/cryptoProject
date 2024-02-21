import java.io.FileInputStream;
import java.io.IOException;

public class GeneratePrime {
    private checkPrime prime;
    private long nBit = 0;

    public long GenPrime(long n, String Filename) {
        long number = 0;
        long minRangeValue = (long) Math.pow(2, n - 1);
        long maxRangeValue = (long) Math.pow(2, n) - 1;
        nBit = n;

        // Validate the input n before proceeding
        if (n < 2) {
            throw new IllegalArgumentException("Error: Cannot generate a prime number with less than 2 bits.");
        }

        prime = new checkPrime();
        StringBuilder binaryString = new StringBuilder();
        try {  
            FileInputStream fis = new FileInputStream(Filename);
            int value;
            boolean foundOne = false;
            while ((value = fis.read()) != -1 && binaryString.length() < n) {
                for (int i = 7; i >= 0 && binaryString.length() < n; i--) {
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
            number = Long.parseLong(binaryString.toString(), 2);
            fis.close();

            if (binaryString.length() < n) {
                throw new IOException("Not enough data to read " + n + " bits.");
            }

            if (!foundOne) {
                throw new IOException("Failed to find a starting bit of 1 in the entire file.");
            }

            // Adjust number to be within range and odd
            if (number % 2 == 0) {
                number += 1;
            }

            // Find the prime number
            while (!prime.isPrime(number)) {
                number += 2; // Always add 2 to stay odd
                if (number >= (maxRangeValue)) {
                    number = minRangeValue + 1; // Wrap back to the minimum of the range and ensure it's odd
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading from file: " + e.getMessage());
        }
        // Output the found prime number
        return number;
    }

    public long getnBit() {
        return nBit;
    }
}