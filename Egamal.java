import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Egamal {
    private BigInteger u;
    private BigInteger p;
    private BigInteger g;
    private BigInteger y;
    private Mod mod = new Mod();
    private findGCD gcd = new findGCD();
    private checkPrime primeCheck = new checkPrime();
    private SecureRandom secureRandom = new SecureRandom();

    public Egamal() {

    }

    // Decrypt
    public Egamal(BigInteger u, BigInteger p) {
        this.u = u;
        this.p = p;
    }

    // Verify
    public Egamal(BigInteger g, BigInteger y, BigInteger p) {
        this.g = g;
        this.y = y;
        this.p = p;
    }

    public BigInteger GenGenerator(BigInteger p) {
        BigInteger g = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE); // [1, p-1]

        while (!CheckGenerator(g, p)) {
            g = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        }
        return g;
    }
    
    private boolean CheckGenerator(BigInteger g, BigInteger p) {
        BigInteger p1 = p.subtract(BigInteger.ONE).divide(BigInteger.TWO); // p1 = (p - 1) / 2
        // System.out.println("Elgamal p1 " +p1);
        if (!primeCheck.isPrime(p1)) {
            throw new IllegalArgumentException("p-1 is not twice a prime number (p is not of the form 2q + 1 where q is prime).");
        } 
        if (mod.FastExpo(g, p1, p).equals(BigInteger.ONE) || !gcd.GCD(g, p).equals(BigInteger.ONE)) {
            return false;
        }
        return true;
    }

    public void ElgamalKeyGen(BigInteger p) throws IOException {
        try (PrintWriter printWriterPK = new PrintWriter("ElgamalPublicKey.txt"); 
            PrintWriter printWriterSK = new PrintWriter("ElgamalSecretKey.txt")) {
            this.p = p;
            // Ensure p is a prime number suitable for cryptography
            if (!primeCheck.isPrime(p)) {
                throw new IllegalArgumentException("p must be a prime number.");
            }

            // Generate g, a generator for Z_p*
            this.g = GenGenerator(p);

            // Select a random private key u from [1, p-1]
            this.u = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.ONE)).add(BigInteger.ONE); // [1, p-1]

            // Compute y = g^u mod p
            this.y = mod.FastExpo(g, u, p);

            // Write u, p, g, y to the file as numbers
            printWriterSK.println("u: " + u.toString() +" ");
            printWriterPK.println("p: " + p.toString() +" ");
            printWriterPK.println("g: " + g.toString() +" ");
            printWriterPK.println("y: " + y.toString() +" ");
        }
    }

    public void ElgamalEncrypt(String inputFilePath, String outputFilePath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
            int character;
            while ((character = fileInputStream.read()) != -1) {

                // Loop to find a 1 <= k < p-1 such that gcd(k, p-1) = 1 for each block.
                BigInteger k = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.ONE);
                
                // while( k >= p-1 || gcd(k, p-1) != 1)
                while (k.compareTo(p.subtract(BigInteger.ONE)) >= 0 || !gcd.GCD(k, p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) { 
                    k = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.ONE);
                }

                // a = g^k mod p
                BigInteger a = mod.FastExpo(g, k, p); 
                // b = y^k * X mod p
                BigInteger b = mod.FastExpo(y, k, p).multiply(BigInteger.valueOf(character)).mod(p); 

                byte[] aBytes = a.toByteArray();
                byte[] bBytes = b.toByteArray();

                // Ensure fixed length
                fileOutputStream.write(aBytes.length);
                fileOutputStream.write(aBytes);

                fileOutputStream.write(bBytes.length);
                fileOutputStream.write(bBytes);
                System.out.println(character +" " +a +" " +b);
            }
        }
    }

    public void ElgamalDecrypt(String inputFilePath, String outputFilePath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
            while (fileInputStream.available() > 0) {
                int aLength = fileInputStream.read();
                byte[] aBytes = new byte[aLength];
                fileInputStream.read(aBytes);
                BigInteger a = new BigInteger(aBytes);

                int bLength = fileInputStream.read();
                byte[] bBytes = new byte[bLength];
                fileInputStream.read(bBytes);
                BigInteger b = new BigInteger(bBytes);
                
                // Compute a^u mod p
                BigInteger au = mod.FastExpo(a, u, p); 
                
                // Compute inverse of a^u mod p
                BigInteger inverseAu = gcd.findInverse(au, p); 
                
                // Compute b * inverse_au mod p
                BigInteger X = b.multiply(inverseAu).mod(p); 
                System.out.println(X);

                fileOutputStream.write(X.intValue());
            }
        }
    }

    public byte[] RWHash(byte[] message) throws NoSuchAlgorithmException {
        // s = output size = log2(p)
        int outputSize = (int) (Math.log(p.doubleValue()) / Math.log(2));

        // Compression block size: 5 * s
        int compressionBlockSize = 5 * outputSize;

        // Convert message bytes to binary string
        StringBuilder paddedMessage = new StringBuilder();
        for (byte b : message) {
            paddedMessage.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }

        // first previous hash value = message.length
        BigInteger previousHash = BigInteger.valueOf(message.length).mod(p);

        // do H0 - H4
        // BigInteger startIndex = BigInteger.ZERO;
        int startIndex = 0;
        for (int i = 0; i < 5; i++) {

            // Split the block into 5 chunks
            String[] chunks = new String[5];
            for (int j = 0; j < 5; j++) {
                if (startIndex + outputSize <= paddedMessage.length()) {
                    chunks[j] = paddedMessage.substring(startIndex, startIndex + outputSize);
                    startIndex += outputSize;
                }
                else {
                    // Padding with 1
                    while (paddedMessage.length() < (startIndex + outputSize)) {
                        paddedMessage.append("1");
                    }
                    chunks[j] = paddedMessage.substring(startIndex, startIndex + outputSize);
                    startIndex += outputSize;
                }
                System.out.println("chunk" +i +" " +j +": " +chunks[j]);
            }

            // Compute sumCi
            BigInteger sumCi = BigInteger.ZERO;
            for (int j = 0; j < 5; j++) {
                if (chunks[j] != null) {
                    BigInteger chunkValue = new BigInteger(chunks[j], 2); // result in binary
                    sumCi = sumCi.add(chunkValue.pow(j + 1)); // ^1, 2, 3, 4, 5
                }
            }
            System.out.println("sumCi " +sumCi);
            BigInteger hashValue = previousHash.add(sumCi).shiftRight(16).mod(p);

            previousHash = hashValue;
        }
        byte[] hashBytes = previousHash.toByteArray();
        return hashBytes;
    }

    public void ElgamalSignature(String inputFilePath, String outputFilePath) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
            
            byte[] messageBytes = fileInputStream.readAllBytes();
            fileInputStream.close();

            BigInteger hashOfMessage = new BigInteger(RWHash(messageBytes));
            
            BigInteger k = new BigInteger(p.bitLength() - 2, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            while (!gcd.GCD(k, p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
                k = new BigInteger(p.bitLength() - 2, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            }
        
            BigInteger a = mod.FastExpo(g, k, p);
            BigInteger kInverse = gcd.findInverse(k, p.subtract(BigInteger.ONE));
            BigInteger b = kInverse.multiply(hashOfMessage.subtract(u.multiply(a))).mod(p.subtract(BigInteger.ONE));
        
            // Convert signature to byte array and write to the file
            byte[] aBytes = a.toByteArray();
            byte[] bBytes = b.toByteArray();

            // Write signature length and signature itself
            fileOutputStream.write(messageBytes);
            fileOutputStream.write(aBytes.length);
            fileOutputStream.write(aBytes);
            fileOutputStream.write(bBytes.length);
            fileOutputStream.write(bBytes);
            fileOutputStream.close();
        }
    }

    public boolean ElgamalVerification(String messageFilePath, String signatureFilePath) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream messageInputStream = new FileInputStream(messageFilePath);
        FileInputStream signatureInputStream = new FileInputStream(signatureFilePath)) {
       
            // Read the message from file and compute its hash
            byte[] messageBytes = messageInputStream.readAllBytes();
            BigInteger hashOfMessage = new BigInteger(RWHash(messageBytes));
            
            // Read the signature from the file
            int aLength = signatureInputStream.read();
            byte[] aBytes = new byte[aLength];
            signatureInputStream.read(aBytes);
            BigInteger a = new BigInteger(aBytes);
            
            int bLength = signatureInputStream.read();
            byte[] bBytes = new byte[bLength];
            signatureInputStream.read(bBytes);
            BigInteger b = new BigInteger(bBytes);
            
            // Verify the signature
            BigInteger leftSide = mod.FastExpo(g, hashOfMessage, p);
            BigInteger rightSide = mod.FastExpo(y, a, p).multiply(mod.FastExpo(a, b, p)).mod(p);
            
            System.out.println(leftSide +" " +rightSide);
            return leftSide.equals(rightSide);
        }
    }       

    public String toString() {
        return "u: " +u +", p: " +p +", g: " +g +", y: " +y;
    }
}