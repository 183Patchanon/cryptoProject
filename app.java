import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class app {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        Egamal egm = new Egamal();
        while(true) {
            Scanner sc = new Scanner(System.in);
            System.out.println("0: Close");
            System.out.println("1: Generate Key");
            System.out.println("2: Elgamal Encryption");
            System.out.println("3: Elgamal Decryption");
            System.out.println("4: Elgamal Sign");
            System.out.println("5: Elgamal Verify");
            System.out.println("6: RWHash");
            System.out.print("mode: ");
            int mode = sc.nextInt();
            /* ******** Genkey ******** */
            if (mode == 0) {
                sc.close();
                break;
            }
            if (mode == 1) {
                System.out.print("n: ");
                BigInteger n = sc.nextBigInteger();
                sc.nextLine(); // newline character
                System.out.print("path: ");
                String path = sc.nextLine();
                
                findGCD fGCD = new findGCD();
                // genPrime
                BigInteger n_path = fGCD.GP.GenPrime(n, path);
                
                System.out.println("******************Genkey******************");
                egm.ElgamalKeyGen(n_path);
                System.out.println(egm.toString());
            }
            else if (mode == 2) {
                System.out.println("******************Encrypt******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PublicKey path: ");
                String publicKeyPath = sc.nextLine();
                egm.ElgamalEncrypt(inputFilePath, publicKeyPath);
                // egm.ElgamalEncrypt("ascii.txt", "ElgamalPublicKey.txt");
            }
            else if (mode == 3) {
                System.out.println("******************Decrypt******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PrivateKey path: ");
                String privateKeyPath = sc.nextLine();
                egm.ElgamalDecrypt(inputFilePath, privateKeyPath);
                // egm.ElgamalDecrypt("cipherText.txt", "ElgamalSecretKey.txt");
            }
            else if (mode == 4) {
                System.out.println("*****************Signature******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PrivateKey path: ");
                String privateKeyPath = sc.nextLine();
                egm.ElgamalSignature(inputFilePath, privateKeyPath);
                // egm.ElgamalSignature("ascii.txt", "ElgamalSecretKey.txt");
            }
            else if (mode == 5) {
                System.out.println("****************Verification****************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PublicKey path: ");
                String publicKeyPath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("SignedMessage path: ");
                String signedMessagePath = sc.nextLine();
                System.out.println(egm.ElgamalVerification(inputFilePath, publicKeyPath, signedMessagePath));
                // System.out.println(egm.ElgamalVerification("ascii.txt","ElgamalPublicKey.txt"));
            }
            else if (mode == 6) {
                System.out.println("*******************RWHash******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                FileInputStream fs = new FileInputStream(inputFilePath);
                byte[] inputRW = fs.readAllBytes();
                System.out.println(egm.RWHash(inputRW));
                fs.close();
            }
        }
    }    
}
