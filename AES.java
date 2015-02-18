/**
 * A 128-bit implementation of the AES cipher (encryption only).
 * Reads a binary file from stdin and outputs the result on stdout.
 * Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
import java.io.DataInputStream;


public class AES {
    private static final int LENGTH_KEY     = 16;       // Key length in bytes
    private static final int LENGTH_DATA    = 16000000; // Maximum plain text length in bytes
    private static final int LENGTH_EXP_KEY = 176;      // Expanded key length in bytes
    private static final int Nb             = 4;        // Number of columns (32-bit words) comprising the state
    private static final int Nk             = 4;        // Number of 32-bit words comprising the cipher key
    private static final int Nr             = 10;       // Number of rounds

    private static byte[] key       = new byte[LENGTH_KEY];     // Encryption key
    private static byte[] plainText = new byte[LENGTH_DATA];    // Unencrypted bytes
    private static byte[] w         = new byte[LENGTH_EXP_KEY]; // Expanded cipher key
    private static byte[][] states;                             // State 'matrices'


    /* 
     * Split the given plain text into an array of states, padding
     * is added as necessary.
     */
    private static void createPlainStates(int textLength) {
        int stateLength = Nb * Nb;

        // Pad with 0s to make it divisible into nb x nb states
        int diff = textLength % stateLength;
        if (diff != 0) textLength += (stateLength - diff);

        states = new byte[textLength][stateLength];

        // Split into multiple states if > state length
        int k = 0;
        for (int i; i < textLength; ++i) {
            for (int j; j < stateLength; ++j) {
                states[i][j] = plainText[k];
                ++k;
            }
        }
    }

    public static void main(String[] args) {
        StringBuilder sb = new StringBuilder();
        int textLength = 0; // Length of plain text

        // Read the bytes from stdin
        DataInputStream dis;
        try {
            dis = new DataInputStream(System.in);
            for (int i = 0; dis.available() > 0 && i < LENGTH_KEY; ++i) {
                key[i] = dis.readByte();
            }
            for (int i = 0; dis.available() > 0; ++i) {
                plainText[i] = dis.readByte();
                ++text_length;
            }
            dis.close();
        } catch (Exception e){
            e.printStackTrace();
        }

        // Expand encryption key
        Rijndael.expandKeys(key, w, Nk * 4, LENGTH_KEY, LENGTH_EXP_KEY);
        // Split plain text into states
        createStates();
        // Encrypt the plain text (states)
        c = encrypt();
        // Append encrypted states into cipher text
        createCipherText()

        // Print key and data
        for (byte b : key) sb.append(String.format("%02X ", b));
        System.out.println(sb);
        sb = new StringBuilder();
        for (byte b : plainText) sb.append(String.format("%02X ", b));
        System.out.println(sb);
    }
}
