/**
 * A 128-bit implementation of the AES cipher (encryption only).
 * Reads a binary file from stdin and outputs the result on stdout.
 * Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
import java.io.DataInputStream;


public class AES {
    private static final int Nb             = 4;        // Number of columns (32-bit words) comprising the state
    private static final int Nk             = 4;        // Number of 32-bit words comprising the cipher key
    private static final int Nr             = 10;       // Number of rounds
    private static final int LENGTH_KEY     = 16;       // Key length in bytes
    private static final int LENGTH_DATA    = 16000000; // Maximum plain text length in bytes
    private static final int LENGTH_EXP_KEY = 176;      // Expanded key length in bytes
    private static final int LENGTH_STATE   = Nb * Nb;  // Length of states in bytes

    private static byte[] key       = new byte[LENGTH_KEY];     // Encryption key
    private static byte[] plainText = new byte[LENGTH_DATA];    // Unencrypted bytes
    private static byte[] w         = new byte[LENGTH_EXP_KEY]; // Expanded cipher key
    private static byte[][] state   = new byte[Nb][Nb];         // State matrix
    private static int textLength   = 0;                        // Length of plain text in bytes
    private static int numStates    = 0;                        // Number of states
    private static int plainTextIt  = 0;                        // Current byte position in plain text
    private static int roundKeyIt   = 0;                        // Current expanded key byte position


    /**
     * Pad the plain text.
     */
    private static void padPlainText() {
        // Pad with 0s to make it divisible into nb x nb states
        int diff = textLength % LENGTH_STATE;
        if (diff != 0) textLength += (LENGTH_STATE - diff);
        numStates = textLength / LENGTH_STATE;
    }

    /**
     * Fill the current state with padded plain text.
     */
    private static void createState() {
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                state[j][i] = plainText[plainTextIt];
                ++plainTextIt;
            }
        }
    }

    /**
     * Combine each byte of the state with a block of the round key using bitwise
     * XOR.
     */
    private static void addRoundKey() {
        // Column-wise XOR of state encryption key
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                state[j][i] = (byte) (state[j][i] ^ w[roundKeyIt]);
                ++roundKeyIt;
            }
        }
    }

    /**
     * Perform a non-linear substitution step by replacing each byte with another
     * according to a lookup table.
     */
    private static void sybBytes() {
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                state[i][j] = (byte) Rijndael.sbox[state[i][j]];
            }
        }
    }

    /**
     * Encrypt the current state.
     */
    private static void encryptState() {
        for (int i; i < Nb; ++i) {
            addRoundKey(); // Initial key round

            for (int k = 1; k < Nr; ++k) {
                subBytes();
                shiftRows();
                mixColumns();
                addRoundKey();
            }

            // Leave out MixColumns for final round
            subBytes();
            shiftRows();
            addRoundKey();
        }
    }

    /**
     * Iteratively encrypt blocks.
     */
    private static void encryptBlocks() {
        // Pad plain text if necessary
        padPlainText();

        for (int i = 0; i < numStates; ++i) {
            // Create one state
            createState();
            // Encrypt the state
            encryptState();
            // Output encrypted block
            // outputState();
        }
    }

    public static void main(String[] args) {
        StringBuilder sb = new StringBuilder();

        // Read the bytes from stdin
        DataInputStream dis;
        try {
            dis = new DataInputStream(System.in);
            for (int i = 0; dis.available() > 0 && i < LENGTH_KEY; ++i) {
                key[i] = dis.readByte();
            }
            for (int i = 0; dis.available() > 0; ++i) {
                plainText[i] = dis.readByte();
                ++textLength;
            }
            dis.close();
        } catch (Exception e){
            e.printStackTrace();
        }

        // Expand encryption key
        Rijndael.expandKeys(key, w, LENGTH_STATE, LENGTH_KEY, LENGTH_EXP_KEY);

        // Start encryption
        encryptBlocks();

        // Print key and data
        for (byte b : key) sb.append(String.format("%02X ", b));
        System.out.println(sb);
        sb = new StringBuilder();
        for (byte b : plainText) sb.append(String.format("%02X ", b));
        System.out.println(sb);
    }
}
