import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
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
                String publicKeyPath = sc.next();
                System.out.print("OutputFile path: ");
                String outputFilePath = sc.next();
                sc.nextLine(); // newline character
                egm.ElgamalEncrypt(inputFilePath, publicKeyPath, outputFilePath);
                // egm.ElgamalEncrypt("ascii.txt", "ElgamalPublicKey.txt");
            }
            else if (mode == 3) {
                System.out.println("******************Decrypt******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PrivateKey path: ");
                String privateKeyPath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("OutputFile path: ");
                String outputFilePath = sc.next();
                sc.nextLine(); // newline character
                egm.ElgamalDecrypt(inputFilePath, privateKeyPath, outputFilePath);
                // egm.ElgamalDecrypt("cipherText.txt", "ElgamalSecretKey.txt");
            }
            else if (mode == 4) {
                System.out.println("*****************Signature******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PrivateKey path: ");
                String privateKeyPath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("Outputfile path: ");
                String outputFilePath = sc.nextLine();
                egm.ElgamalSignature(inputFilePath, privateKeyPath, outputFilePath);
                // egm.ElgamalSignature("ascii.txt", "ElgamalSecretKey.txt");
            }
            else if (mode == 5) {
                System.out.println("****************Verification****************");
                System.out.print("SignedMessage path: ");
                String signedMessagePath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("PublicKey path: ");
                String publicKeyPath = sc.next();
                sc.nextLine(); // newline character
                System.out.print("Outputfile path: ");
                String outputFilePath = sc.nextLine();
                System.out.println(egm.ElgamalVerification(signedMessagePath, publicKeyPath, outputFilePath));
                // System.out.println(egm.ElgamalVerification("ascii.txt","ElgamalPublicKey.txt"));
            }
            else if (mode == 6) {
                System.out.println("*******************RWHash******************");
                System.out.print("InputFile path: ");
                String inputFilePath = sc.next();
                sc.nextLine();
                System.out.print("p path: ");
                String pPath = sc.nextLine();

                FileInputStream fs = new FileInputStream(inputFilePath);
                byte[] inputRW = fs.readAllBytes();
                System.out.println(egm.getRWHash(inputRW, pPath));
                fs.close();
            }
        }
    }    
}
