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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

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

    // real
    /* public void ElgamalEncrypt(String inputFilePath, String publicKeyPath, String outputFilePath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
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
                // System.out.println(aBytes.length +" " +bBytes.length);
                // System.out.println(character +" " +a +" " +b);
            }
        }
    } */


    // real
    /* public void ElgamalDecrypt(String inputFilePath, String secretKeyPath, String outputFilePath) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
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
                // System.out.println(X)

                fileOutputStream.write(X.intValue());
            }
        }
    } */

    public void ElgamalEncrypt(String inputFilePath, String publicKeyPath, String outputFilePath) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(publicKeyPath))) {
            p = new BigInteger(br.readLine().split(": ")[1].trim());
            g = new BigInteger(br.readLine().split(": ")[1].trim());
            y = new BigInteger(br.readLine().split(": ")[1].trim());
        }

        // Reading and converting the plain text to blocks of BigInteger
        Path path = Paths.get(inputFilePath);
        byte[] data = Files.readAllBytes(path);
        String bitsString = bytesToBitsBinary(data);
        List<BigInteger> block = new ArrayList<>();
        int blocksize = p.bitLength() - 1;

        for (int i = 0; i < bitsString.length(); i += blocksize) {
            int endIndex = Math.min(i + blocksize, bitsString.length());
            String tmp = bitsString.substring(i, endIndex); // i - (i + blocksize)
            if (tmp.length() != blocksize) {
                tmp += "0".repeat(blocksize - tmp.length()); // post-padding with 0
            }
            block.add(new BigInteger(tmp, 2)); // create bigInt of every block
        }

        // Encrypting the blocks
        List<Map<String, BigInteger>> cipher = encrypt(block);

        // Writing the cipher to a file
        try (FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath)) {
            StringBuilder res = new StringBuilder();
            blocksize = p.bitLength();

            for (Map<String, BigInteger> tmp : cipher) {
                String a = tmp.get("a").toString(2); //.get(key) -> return value
                String b = tmp.get("b").toString(2);
                res.append("0".repeat(blocksize - a.length())).append(a); // pre-padding with 0
                res.append("0".repeat(blocksize - b.length())).append(b);
            }

            byte[] resBytes = bitsToBytes(res.toString());
            fileOutputStream.write(resBytes);
        }
    }

    private List<Map<String, BigInteger>> encrypt(List<BigInteger> plainText) {
        List<Map<String, BigInteger>> cipher = new ArrayList<>();
        for (BigInteger x : plainText) {
            SecureRandom random = new SecureRandom();
            BigInteger k = new BigInteger(p.bitLength(), random);
            while (k.compareTo(p.subtract(BigInteger.ONE)) >= 0 || k.compareTo(BigInteger.TWO) < 0 || !(k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE))) {
                k = new BigInteger(p.bitLength(), random);
            }

            BigInteger a = mod.FastExpo(g, k, p);
            BigInteger b = (mod.FastExpo(y, k, p).multiply(x)).mod(p);
            cipher.add(Map.of("a", a, "b", b));
        }
        return cipher;
    }

    public void ElgamalDecrypt(String inputFilePath, String secretKeyPath, String outputFilePath) throws IOException {   
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream(outputFilePath);
             BufferedReader br = new BufferedReader(new FileReader(secretKeyPath))) {
            u = new BigInteger(br.readLine().split(": ")[1].trim());
            p = new BigInteger(br.readLine().split(": ")[1].trim());

            // Read the cipher text
            byte[] data = fileInputStream.readAllBytes();
            String bitsString = bytesToBitsBinary(data);
            List<Map<String, BigInteger>> cipher = new ArrayList<>();
            int blocksize = p.bitLength();

            // Process cipher text
            for (int i = 0; i < bitsString.length(); i += 2 * blocksize) {
                if (i + blocksize <= bitsString.length()) {
                    // seperate a and b
                    BigInteger a = new BigInteger(bitsString.substring(i, i + blocksize), 2);
                    BigInteger b = new BigInteger(bitsString.substring(i + blocksize, Math.min(i + 2 * blocksize, bitsString.length())), 2);
                    cipher.add(Map.of("a", a, "b", b));
                }
            }

            // Decrypt the cipher text
            List<BigInteger> plainText = new ArrayList<>();
            for (Map<String, BigInteger> tmp : cipher) {
                BigInteger a = tmp.get("a");
                BigInteger au = mod.FastExpo(a, u, p);
                BigInteger invAu = gcd.findInverse(au, p);

                BigInteger b = tmp.get("b");

                BigInteger decrypted = invAu.multiply(b).mod(p);
                plainText.add(decrypted);
            }
            // Write the plain text to file
            StringBuilder res = new StringBuilder();
            int blocksizeBits = p.bitLength() - 1;
            for (BigInteger tmp : plainText) {
                String pt = tmp.toString(2);
                res.append("0".repeat(Math.max(0, blocksizeBits - pt.length()))).append(pt); // pre-padding with 0
            }

            byte[] resBytes = bitsToBytes(res.toString());
            fileOutputStream.write(resBytes);
        }
    }

    public byte[] getRWHash(byte[] message, String pPath) throws FileNotFoundException, IOException, NoSuchAlgorithmException {
        BufferedReader br = new BufferedReader(new FileReader(pPath));
        p = new BigInteger(br.readLine().split(": ")[1].trim());
        br.close();
        byte[] hash = RWHash(message);
        return hash;
    }

    private byte[] RWHash(byte[] message) throws NoSuchAlgorithmException, FileNotFoundException, IOException {

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
        int iterations = (int) paddedMessage.length() / compressionBlockSize;

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
                // System.out.println("chunk" +i +" " +j +": " +chunks[j]);
            }

            // Compute sumCi
            BigInteger sumCi = BigInteger.ZERO;
            for (int j = 0; j < 5; j++) {
                if (chunks[j] != null) {
                    BigInteger chunkValue = new BigInteger(chunks[j], 2); // result in binary
                    sumCi = sumCi.add(chunkValue.pow(j + 1)); // ^1, 2, 3, 4, 5
                }
            }
            // System.out.println("sumCi " +sumCi);
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

    public void ElgamalSignature(String inputFilePath, String secretKeyPath, String fileoutputPath) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream fileInputStream = new FileInputStream(inputFilePath);
             FileOutputStream fileOutputStream = new FileOutputStream(fileoutputPath)) {
            BufferedReader br = new BufferedReader(new FileReader(secretKeyPath));
            u = new BigInteger(br.readLine().split(": ")[1].trim());
            p = new BigInteger(br.readLine().split(": ")[1].trim());
            g = new BigInteger(br.readLine().split(": ")[1].trim());
            y = new BigInteger(br.readLine().split(": ")[1].trim());
            br.close();
            byte[] messageBytes = fileInputStream.readAllBytes();

            BigInteger hashOfMessage = new BigInteger(RWHash(messageBytes)); // Assuming RWHash function is defined elsewhere
            
            SecureRandom secureRandom = new SecureRandom(); // Ensure secureRandom is initialized properly
            BigInteger k = new BigInteger(p.bitLength() - 2, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            while (!gcd.GCD(k, p.subtract(BigInteger.ONE)).equals(BigInteger.ONE)) { // Assuming GCD function is defined elsewhere
                k = new BigInteger(p.bitLength() - 2, secureRandom).mod(p.subtract(BigInteger.TWO)).add(BigInteger.TWO);
            }
            
            BigInteger r = mod.FastExpo(g, k, p); // Assuming FastExpo function is defined elsewhere
            BigInteger kInverse = gcd.findInverse(k, p.subtract(BigInteger.ONE)); // Assuming findInverse function is defined elsewhere
            BigInteger s = kInverse.multiply(hashOfMessage.subtract(u.multiply(r))).mod(p.subtract(BigInteger.ONE));
            
            // Convert signature to byte array
            byte[] rBytes = r.toByteArray();
            byte[] sBytes = s.toByteArray();

            fileOutputStream.write(messageBytes);
            fileOutputStream.write(rBytes);
            fileOutputStream.write(sBytes);

            fileOutputStream.write(rBytes.length);
            fileOutputStream.write(sBytes.length);
        }
    }

    public boolean ElgamalVerification(String signedMessage, String publicKeyPath, String fileoutputPath) throws IOException, NoSuchAlgorithmException {
        try (FileInputStream signedInputStream = new FileInputStream(signedMessage)) {
            // Read public key to get p, g, y
            BufferedReader br = new BufferedReader(new FileReader(publicKeyPath));
            p = new BigInteger(br.readLine().split(": ")[1].trim());
            g = new BigInteger(br.readLine().split(": ")[1].trim()); 
            y = new BigInteger(br.readLine().split(": ")[1].trim());
            br.close();

            byte[] signedContent = signedInputStream.readAllBytes();
            
            // Assuming the last two bytes indicate the lengths of a and b
            int rLength = signedContent[signedContent.length - 2] & 0xFF; // Convert to unsigned (only positive number)
            int sLength = signedContent[signedContent.length - 1] & 0xFF; // Convert to unsigned

            // Calculate where the message ends and the signature begins
            int messageLength = signedContent.length - rLength - sLength - 2;
            
            byte[] messageBytes = Arrays.copyOfRange(signedContent, 0, messageLength);
            byte[] rBytes = Arrays.copyOfRange(signedContent, messageLength, messageLength + rLength);
            byte[] sBytes = Arrays.copyOfRange(signedContent, messageLength + sLength, messageLength + rLength + sLength);
            
            // Hash the message
            BigInteger hashOfMessage = new BigInteger(RWHash(messageBytes));
            
            // Extract a and b from the signature
            BigInteger r = new BigInteger(rBytes);
            BigInteger s = new BigInteger(sBytes);
            
            // Verify the signature
            BigInteger leftSide = mod.FastExpo(g, hashOfMessage, p);
            BigInteger rightSide = mod.FastExpo(y, r, p).multiply(mod.FastExpo(r, s, p)).mod(p);
            
            if (leftSide.equals(rightSide)) {
                // If verification is successful, write the message (without the signature) to the specified output file
                try (FileOutputStream fileOutputStream = new FileOutputStream(fileoutputPath)) {
                    fileOutputStream.write(messageBytes);
                }
                return true; // Verification succeeded and file written
            } else {
                return false; // Verification failed
            }
        }
    }

    public String toString() {
        return "u: " +u +", p: " +p +", g: " +g +", y: " +y;
    }

    public static String bytesToBitsBinary(byte[] byteData) {
        StringBuilder bitsData = new StringBuilder();
        for (byte b : byteData) {
            bitsData.append(String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0'));
        }
        return bitsData.toString();
    }

    public static byte[] bitsToBytes(String bitString) {
        if (bitString.length() % 8 != 0) {
            bitString = bitString + "0".repeat(8 - (bitString.length() % 8)); // post-padding with 0
        }
        List<Byte> byteValues = new ArrayList<>();
        for (int i = 0; i < bitString.length(); i += 8) {
            String chunk = bitString.substring(i, Math.min(i + 8, bitString.length()));
            byteValues.add((byte) Integer.parseInt(chunk, 2));
        }
        while (byteValues.get(byteValues.size() - 1) == 0) {
            byteValues.remove(byteValues.size() - 1);
        }
        byte[] byteArray = new byte[byteValues.size()];
        for (int i = 0; i < byteValues.size(); i++) {
            byteArray[i] = byteValues.get(i);
        }
        return byteArray;
    }
}