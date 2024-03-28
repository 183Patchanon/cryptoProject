import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

public class appDecrypt {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {

        System.out.println("*******************Decrypt*******************");
        // Egamal egm = new Egamal(BigInteger.valueOf(266177211), BigInteger.valueOf(536871263));
        // egm.ElgamalDecrypt("cipherText.txt", "plainText.txt");
        
        System.out.println("****************Verification****************");
        Egamal egm = new Egamal(BigInteger.valueOf(154), BigInteger.valueOf(268), BigInteger.valueOf(563));
        System.out.println(egm.ElgamalVerification("ascii.txt","Signature.txt"));
    }
}
