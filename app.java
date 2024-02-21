import java.util.Scanner;

public class app {
    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        System.out.print("n: ");
        int n = sc.nextInt();
        sc.nextLine(); // newline character
        System.out.print("path: ");
        String path = sc.nextLine();

        sc.close();
        
        findGCD fGCD = new findGCD();

        // genPrime
        long tmp = fGCD.GP.GenPrime(n, path);
        System.out.println(tmp);
        
        long result[] = fGCD.GenRandomNowithInverse(tmp);
        for (int i = 0; i < 3; i++) {
            System.out.println(result[i]);
        }
        
        // GCD
        // System.out.println(fGCD.GCD(365, 1013));

        // Inverse
        // System.out.println(fGCD.findInverse(365, 1013));
    }
}