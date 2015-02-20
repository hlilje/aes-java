/**
 * A 128-bit implementation of the AES cipher (encryption only).
 * Reads a binary file from stdin and outputs the result on stdout.
 * Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
import java.io.DataInputStream;


public class AES {
    private static final int Nb             = 4;                        // Number of columns (32-bit words) comprising the state
    private static final int Nk             = 4;                        // Number of 32-bit words comprising the cipher key
    private static final int Nr             = 10;                       // Number of rounds
    private static final int LENGTH_DATA    = 16000000;                 // Maximum plain text length in bytes
    private static final int LENGTH_KEY     = Nk * 4;                   // Key length in bytes
    private static final int LENGTH_EXP_KEY = Nb * (Nr + 1) * 4;        // Expanded key length in bytes
    private static final int LENGTH_STATE   = Nb * Nb;                  // Length of states in bytes
    private static final byte[] key         = new byte[LENGTH_KEY];     // Encryption key
    private static final byte[] plainText   = new byte[LENGTH_DATA];    // Unencrypted bytes
    private static final byte[] w           = new byte[LENGTH_EXP_KEY]; // Expanded cipher key
    private static final byte[][] state     = new byte[Nb][Nb];         // State matrix
    private static final byte[] E           = new byte[256];            // Exp table (base 0x03)
    private static final byte[] L           = new byte[256];            // Log table (base 0x03)

    private static int textLength  = 0; // Length of plain text in bytes
    private static int numStates   = 0; // Number of states
    private static int plainTextIt = 0; // Current byte position in plain text


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
    private static void addRoundKey(int encRound) {
        byte[] roundKey = new byte[LENGTH_STATE];
        int encRoundOffset = encRound * LENGTH_STATE;
        // Extract the transpose key to get order as columns instead of rows
        for (int i = 0; i < Nk; ++i) {
            for (int j = 0; j < Nk; ++j)
                roundKey[j*Nk+i] = w[encRoundOffset+i*Nk+j];
        }

        // XOR state with encryption key
        int k = 0;
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                state[i][j] = (byte) (state[i][j] ^ roundKey[k]);
                ++k;
            }
        }
    }

    /**
     * Perform a non-linear substitution step by replacing each byte with another
     * according to a lookup table.
     */
    private static void subBytes() {
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                state[j][i] = (byte) Rijndael.sbox[state[j][i] & 0xFF];
            }
        }
    }

    /**
     * Perform a transposition step where the last three rows of the state are
     * shifted cyclically a certain number of steps.
     */
    private static void shiftRows() {
        byte[] buffer = new byte[3];
        for (int i = 1; i < Nb; ++i) {
            int toCopy = i; // Avoid recreating buffer
            System.arraycopy(state[i], 0, buffer, 0, i);
            System.arraycopy(state[i], i, state[i], 0, state[i].length - i);
            System.arraycopy(buffer, 0, state[i], state[i].length - i, toCopy);
        }
    }

    /**
     * Multiplication in the Galois field GF(2^8).
     */
    private static byte galoisMult(byte a, byte b) {
        int p = 0;
        int hiBitSet = 0;
        for (int i = 0; i < 8; ++i) {
            if ((b & 1) == 1)
                p ^= a;
            hiBitSet = a & 0x80;
            a <<= 1;
            if (hiBitSet == 0x80)
                a ^= 0x1b;
            b >>= 1;
        }
        return (byte) (p % 256);
    }

    /**
     * Create and load the E table.
     */
    private static void loadE() {
        byte x = (byte) 0x01;
        int index = 0;
        E[index++] = (byte) 0x01;
        for (int i = 0; i < 255; i++) {
            byte y = fastMult(x, (byte) 0x03);
            E[index++] = y;
            x = y;
        }
    }

    /**
     * Load the L table using the E table.
     */
    private static void loadL() {
        int index;
        for (int i = 0; i < 255; i++) {
            L[E[i] & 0xff] = (byte)i;
        }
    }

    /**
     * Fast multiply using table lookup.
     */
    private static byte fastMult(byte a, byte b){
        int t = 0;;
        if (a == 0 || b == 0) return 0;
        t = (L[(a & 0xff)] & 0xff) + (L[(b & 0xff)] & 0xff);
        if (t > 255) t = t - 255;
        return E[(t & 0xff)];
    }

    /**
     * Mix one column by by considering it as a polynomial and performing
     * operations in the Galois field (2^8).
     */
    private static void mixColumns() {
        // Store temporary column for operations
        byte[] temp = new byte[Nb];
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                temp[j] = state[j][i];
            }
            // XOR is addition in this field
            // state[0][i] = (byte) (galoisMult(temp[0], (byte) 2) ^ galoisMult(temp[1], (byte) 3) ^
            //                       galoisMult(temp[2], (byte) 1) ^ galoisMult(temp[3], (byte) 1));
            // state[1][i] = (byte) (galoisMult(temp[0], (byte) 1) ^ galoisMult(temp[1], (byte) 2) ^
            //                       galoisMult(temp[2], (byte) 3) ^ galoisMult(temp[3], (byte) 1));
            // state[2][i] = (byte) (galoisMult(temp[0], (byte) 1) ^ galoisMult(temp[1], (byte) 1) ^
            //                       galoisMult(temp[2], (byte) 2) ^ galoisMult(temp[3], (byte) 3));
            // state[3][i] = (byte) (galoisMult(temp[0], (byte) 3) ^ galoisMult(temp[1], (byte) 1) ^
            //                       galoisMult(temp[2], (byte) 1) ^ galoisMult(temp[3], (byte) 2));
            state[0][i] = (byte) (fastMult(temp[0], (byte) 2) ^ fastMult(temp[1], (byte) 3) ^
                    fastMult(temp[2], (byte) 1) ^ fastMult(temp[3], (byte) 1));
            state[1][i] = (byte) (fastMult(temp[0], (byte) 1) ^ fastMult(temp[1], (byte) 2) ^
                    fastMult(temp[2], (byte) 3) ^ fastMult(temp[3], (byte) 1));
            state[2][i] = (byte) (fastMult(temp[0], (byte) 1) ^ fastMult(temp[1], (byte) 1) ^
                    fastMult(temp[2], (byte) 2) ^ fastMult(temp[3], (byte) 3));
            state[3][i] = (byte) (fastMult(temp[0], (byte) 3) ^ fastMult(temp[1], (byte) 1) ^
                    fastMult(temp[2], (byte) 1) ^ fastMult(temp[3], (byte) 2));
        }
    }

    /**
     * Encrypt the current state.
     */
    private static void encryptState() {
        addRoundKey(0); // Initial key round

        for (int j = 1; j < Nr; ++j) {
            subBytes();
            shiftRows();
            mixColumns();
            addRoundKey(j);
        }

        // Leave out MixColumns for final round
        subBytes();
        shiftRows();
        addRoundKey(Nr);
    }

    /**
     * Print the encrypted state to stdout.
     */
    private static void outputState() {
        StringBuilder sb = new StringBuilder(); // DEBUG
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                // System.out.write(state[j][i]);
                sb.append(String.format("%02X ", state[j][i])); // DEBUG
            }
        }
        // System.out.flush();
        // DEBUG
        System.out.println("Result:");
        System.out.println(sb);
    }

    /**
     * Iteratively encrypt all states (blocks).
     */
    private static void encrypt() {
        for (int i = 0; i < numStates; ++i) {
            // Create one state
            createState();
            // Encrypt the state
            encryptState();
            // Output encrypted block
            outputState();
        }
    }

    public static void main(String[] args) {
        // Read the key and plain text bytes from stdin
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

        // DEBUG
        // StringBuilder sb = new StringBuilder();
        // System.out.println("Plain text:");
        // for (int i = 0; i < textLength; ++i) sb.append(String.format("%02X ", plainText[i]));
        // System.out.println(sb);

        // Pad plain text if necessary
        padPlainText();

        // Expand encryption key
        Rijndael.expandKey(key, w, LENGTH_STATE, LENGTH_KEY, LENGTH_EXP_KEY);

        // DEBUG
        // sb = new StringBuilder();
        // System.out.println("Key:");
        // for (byte b : key) sb.append(String.format("%02X ", b));
        // System.out.println(sb);

        // Init fast multiplication tables
        loadE();
        loadL();

        // Start encryption
        encrypt();
    }
}
