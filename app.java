import java.util.Scanner;
import java.io.IOException;
import java.math.BigInteger;

public class app {
    public static void main(String[] args) throws IOException {
        Scanner sc = new Scanner(System.in);
        System.out.print("n: ");
        BigInteger n = sc.nextBigInteger();
        sc.nextLine(); // newline character
        System.out.print("path: ");
        String path = sc.nextLine();

        sc.close();
        
        findGCD fGCD = new findGCD();

        // genPrime
        BigInteger tmp = fGCD.GP.GenPrime(n, path);
        // System.out.println(tmp);
        
        /* long result[] = fGCD.GenRandomNowithInverse(tmp);
        for (int i = 0; i < 3; i++) {
            System.out.println(result[i]);
        } */
        
        // GCD
        // System.out.println(fGCD.GCD(365, 1013));

        // Inverse
        // System.out.println(fGCD.findInverse(365, 1013));

        /* ******** Elgamal ******** */
        System.out.println("******************Elgamal******************");
        Egamal egm = new Egamal();
        // System.out.println("Elgamal g " +egm.GenGenerator(tmp));
        egm.ElgamalKeyGen(tmp);
        System.out.println(egm.toString());

        egm.ElgamalEncrypt("ascii.txt", "cipherText.txt");
        System.out.println("*******************decrypt*******************");
        egm.ElgamalDecrypt("cipherText.txt", "plainText.txt");
    }
}