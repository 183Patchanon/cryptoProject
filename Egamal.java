import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Egamal {
    private BigInteger u;
    private BigInteger p;
    private BigInteger g;
    private BigInteger y;
    private Mod mod = new Mod();
    private findGCD gcd = new findGCD();
    private checkPrime primeCheck = new checkPrime();
    private SecureRandom secureRandom = new SecureRandom();

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
            printWriterSK.println("p: " + p.toString() +" ");
            printWriterSK.println("g: " + g.toString() +" ");
            printWriterSK.println("y: " + y.toString() +" ");

            printWriterPK.println("p: " + p.toString() +" ");
            printWriterPK.println("g: " + g.toString() +" ");
            printWriterPK.println("y: " + y.toString() +" ");
        }
    }
    public void ElgamalEncrypt(String inputFilePath, String publicKeyPath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream("CipherText.txt")) {
            BufferedReader br = new BufferedReader(new FileReader(publicKeyPath));
            BigInteger p = new BigInteger(br.readLine().split(": ")[1].trim());
            BigInteger g = new BigInteger(br.readLine().split(": ")[1].trim());
            BigInteger y = new BigInteger(br.readLine().split(": ")[1].trim());
            br.close();
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

    /* public void ElgamalEncrypt(String inputFilePath, String publicKeyPath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
        FileOutputStream fileOutputStream = new FileOutputStream("CipherText.txt");
             BufferedReader br = new BufferedReader(new FileReader(publicKeyPath))) {
            p = new BigInteger(br.readLine().split(": ")[1].trim());
            g = new BigInteger(br.readLine().split(": ")[1].trim());
            y = new BigInteger(br.readLine().split(": ")[1].trim());

            int bytesRead;
            int blockSize = (int) Math.ceil((double) (p.bitLength() - 1) / 8); // The block size is computed by dividing (p.bitLength() - 1) by 8 and rounding up
            byte[] block = new byte[blockSize];

            while ((bytesRead = fileInputStream.read(block)) != -1) {

                // Encryption logic remains the same...
                BigInteger k = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.ONE);
                while (k.compareTo(p.subtract(BigInteger.ONE)) >= 0 || !gcd.GCD(k, p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) {
                    k = new BigInteger(p.bitLength() - 1, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.ONE);
                }
                BigInteger a = mod.FastExpo(g, k, p); 
                BigInteger b = mod.FastExpo(y, k, p).multiply(new BigInteger(1, block)).mod(p);

                // byte[] aBytes = a.toByteArray();
                // byte[] bBytes = b.toByteArray();
                byte[] aBytes = adjustByteLength(a.toByteArray(), blockSize);
                byte[] bBytes = adjustByteLength(b.toByteArray(), blockSize);

                System.out.println(aBytes.length +" " +bBytes.length);
                fileOutputStream.write(aBytes);
                fileOutputStream.write(bBytes);
            }
        }
    }

    // pre-zero-padding
    private byte[] adjustByteLength(byte[] original, int length) {
        if (original.length < length) {
            byte[] result = new byte[length];
            System.arraycopy(original, 0, result, length - original.length, original.length);
            return result;
        }
        return original;
    }

    public void ElgamalDecrypt(String inputFilePath, String secretKeyPath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
            FileOutputStream fileOutputStream = new FileOutputStream("plainText.txt");
            BufferedReader br = new BufferedReader(new FileReader(secretKeyPath))) {
            BigInteger u = new BigInteger(br.readLine().split(": ")[1].trim());
            BigInteger p = new BigInteger(br.readLine().split(": ")[1].trim());

            int blockSize = (int) Math.ceil((double) (p.bitLength() - 1) / 8);

            while (fileInputStream.available() > 0) {
                byte[] aBytes = new byte[blockSize];
                fileInputStream.read(aBytes);
                BigInteger a = new BigInteger(1, aBytes);

                byte[] bBytes = new byte[blockSize];
                fileInputStream.read(bBytes);
                BigInteger b = new BigInteger(1, bBytes);

                // Decrypt process...
                BigInteger au = mod.FastExpo(a, u, p);
                BigInteger inverseAu = gcd.findInverse(au, p);
                BigInteger X = b.multiply(inverseAu).mod(p);

                byte[] decryptedBlock = X.toByteArray();
                fileOutputStream.write(decryptedBlock);
            }
        }
    } */

    public void ElgamalDecrypt(String inputFilePath, String secretKeyPath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
            FileOutputStream fileOutputStream = new FileOutputStream("plainText.txt")) {
            BufferedReader br = new BufferedReader(new FileReader(secretKeyPath));
            u = new BigInteger(br.readLine().split(": ")[1].trim());
            p = new BigInteger(br.readLine().split(": ")[1].trim());
            g = new BigInteger(br.readLine().split(": ")[1].trim());
            y = new BigInteger(br.readLine().split(": ")[1].trim());
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

    /* public void ElgamalDecrypt(String inputFilePath, String secretKeyPath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream("plainText.txt")) {
            BufferedReader br = new BufferedReader(new FileReader(secretKeyPath));
            BigInteger u = new BigInteger(br.readLine().split(": ")[1].trim());
            BigInteger p = new BigInteger(br.readLine().split(": ")[1].trim());
            BigInteger g = new BigInteger(br.readLine().split(": ")[1].trim());
            BigInteger y = new BigInteger(br.readLine().split(": ")[1].trim());

            int blockSize = (int) Math.ceil((double) (p.bitLength() - 1) / 8); // The block size is computed by dividing (p.bitLength() - 1) by 8 and rounding up
            while (fileInputStream.available() > 0) {
                byte[] aBytes = new byte[blockSize];
                fileInputStream.read(aBytes);
                BigInteger a = new BigInteger(aBytes);

                byte[] bBytes = new byte[blockSize];
                fileInputStream.read(bBytes);
                BigInteger b = new BigInteger(bBytes);
                
                // Compute a^u mod p
                BigInteger au = mod.FastExpo(a, u, p); 
                
                // Compute inverse of a^u mod p
                BigInteger inverseAu = gcd.findInverse(au, p); 
                
                // Compute b * inverse_au mod p
                BigInteger X = b.multiply(inverseAu).mod(p); 
                // System.out.println(X);

                fileOutputStream.write(X.intValue());
            }
        }
    } */

    public byte[] RWHash(byte[] message) throws NoSuchAlgorithmException, FileNotFoundException, IOException {
        // p = new BigInteger("2147483783");
        // s = output size = log2(p)
        System.out.println(p);
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

        // Calculate the number of iterations required based on the length of the paddedMessage
        int iterations = (int) Math.ceil((double) paddedMessage.length() / compressionBlockSize);

        // do H0 - H4
        // BigInteger startIndex = BigInteger.ZERO;
        int startIndex = 0;
        for (int i = 0; i < iterations; i++) {

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
        
        // Convert final hash to hexadecimal string
        String hashHex = previousHash.toString(16);

        // Write the hexadecimal hash to a file
        try (FileOutputStream fo = new FileOutputStream("RWHash.txt")) {
            fo.write(hashHex.getBytes());
        }

        return hashBytes;
    }

    public void ElgamalSignature(String inputFilePath, String secretKeyPath) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
            FileOutputStream fileOutputStream = new FileOutputStream("signedMessage.txt")) {
            BufferedReader br = new BufferedReader(new FileReader(secretKeyPath));
            u = new BigInteger(br.readLine().split(": ")[1].trim());
            p = new BigInteger(br.readLine().split(": ")[1].trim());
            g = new BigInteger(br.readLine().split(": ")[1].trim());
            y = new BigInteger(br.readLine().split(": ")[1].trim());
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
            fileOutputStream.write(aBytes);
            fileOutputStream.write(bBytes);
            fileOutputStream.close();
        }
    }

    public boolean ElgamalVerification(String messageFilePath, String publicKeyPath, String signedMessage) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream messageInputStream = new FileInputStream(messageFilePath);
            FileInputStream signedInputStream = new FileInputStream(signedMessage)) {
            // Read the entire file content
            byte[] fileContent = messageInputStream.readAllBytes();
            byte[] signedContent = signedInputStream.readAllBytes();
    
            // Read public key to get p, y
            BufferedReader publicKeyReader = new BufferedReader(new FileReader(publicKeyPath));
            p = new BigInteger(publicKeyReader.readLine().split(": ")[1].trim());
            g = new BigInteger(publicKeyReader.readLine().split(": ")[1].trim()); // Unused in verification
            y = new BigInteger(publicKeyReader.readLine().split(": ")[1].trim());
    
            publicKeyReader.close();
    
            // Assume the message is in the first part of the file and the signature is in the last part
            // Find the end of the message part by searching for a delimiter or by other means
            // For simplicity, let's assume we have the lengths of the message and signature
            int messageLength = fileContent.length;
            byte[] messageBytes = Arrays.copyOfRange(fileContent, 0, messageLength);
    
            // Assuming signature is at the end and we know its length
            int signatureStart = messageLength;
            byte[] signatureBytes = Arrays.copyOfRange(signedContent, signatureStart, signedContent.length);
    
            // Hash the message
            BigInteger hashOfMessage = new BigInteger(RWHash(messageBytes));
    
            // Extract a and b from signature
            BigInteger a = new BigInteger(1, Arrays.copyOfRange(signatureBytes, 0, signatureBytes.length / 2));
            BigInteger b = new BigInteger(1, Arrays.copyOfRange(signatureBytes, signatureBytes.length / 2, signatureBytes.length));
    
            // Verify the signature
            BigInteger leftSide = mod.FastExpo(g, hashOfMessage, p);
            BigInteger rightSide = mod.FastExpo(y, a, p).multiply(mod.FastExpo(a, b, p)).mod(p);
    
            return leftSide.equals(rightSide);
        }
    }

    /* public boolean ElgamalVerification(String messageFilePath, String publicKeyPath) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream messageInputStream = new FileInputStream(messageFilePath);
        FileInputStream signatureInputStream = new FileInputStream("verifiedMesage.txt")) {
       
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
    }   */     

    public String toString() {
        return "u: " +u +", p: " +p +", g: " +g +", y: " +y;
    }
}