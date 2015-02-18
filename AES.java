/**
 * A 128-bit implementation of the AES cipher (encryption only).
 * Reads a binary file from stdin and outputs the result on stdout.
 * Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
import java.io.DataInputStream;


public class AES {
    private static final int KEY_LENGTH = 16;       // Key length in bytes
    private static final int MAX_DATA   = 16000000; // Maximum plain text size in bytes
    public static final int Nb          = 4;        // Number of columns (32-bit words) comprising the state
    public static final int Nk          = 4;        // Number of 32-bit words comprising the cipher key
    public static final int Nr          = 10;       // Number of rounds

    public static byte[] w; // Expanded cipher key

    public static void main(String[] args) {
        byte[] key       = new byte[KEY_LENGTH];
        byte[] plainText = new byte[16000000];
        StringBuilder sb = new StringBuilder();

        // Read the bytes from stdin
        DataInputStream dis;
        try {
            dis = new DataInputStream(System.in);
            for (int i = 0; dis.available() > 0 && i < KEY_LENGTH; ++i) {
                key[i] = dis.readByte();
            }
            for (int i = 0; dis.available() > 0; ++i) {
                plainText[i] = dis.readByte();
            }
            dis.close();
        } catch (Exception e){
            e.printStackTrace();
        }

        // Print key and data
        for (byte b : key) sb.append(String.format("%02X ", b));
        System.out.println(sb);
        sb = new StringBuilder();
        for (byte b : plainText) sb.append(String.format("%02X ", b));
        System.out.println(sb);
    }
}
