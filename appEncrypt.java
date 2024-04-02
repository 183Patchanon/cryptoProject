import java.util.Scanner;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class appEncrypt {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        /* ******** Elgama ******** */
        System.out.println("******************Encrypt******************");
        Egamal encrypt = new Egamal(BigInteger.valueOf(229), BigInteger.valueOf(98), BigInteger.valueOf(563));
        encrypt.ElgamalEncrypt("ascii.txt", "cipherText.txt");

        System.out.println("*****************Signature******************");
        // egm.ElgamalSignature("ascii.txt", "Signature.txt");

        // System.out.println(egm.RWHash("?ABCabcAAAAAAA".getBytes()));
    }
}