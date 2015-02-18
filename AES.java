/**
 * A 128-bit implementation of the AES cipher (encryption only).
 * Reads a binary file from stdin and outputs the result on stdout.
 * Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
import java.io.*;


public class AES {

    private static final int KEY_LENGTH = 16; // Key length in bytes

    public static void main(String[] args) {
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        String s;
        try {
            while ((s = in.readLine()) != null && s.length() != 0)
                System.out.println(s);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }
}
