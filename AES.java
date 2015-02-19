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

    private static int textLength   = 0; // Length of plain text in bytes
    private static int numStates    = 0; // Number of states
    private static int plainTextIt  = 0; // Current byte position in plain text


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
    private static void addRoundKey(int encRound, int offset) {
        byte[] roundKey = new byte[offset];
        int encRoundOffset = encRound * offset;
        // Extract the transpose key to get order as columns instead of rows
        for (int i = 0; i < Nk; ++i) {
            for (int j = 0; j < Nk; ++j)
                roundKey[j*Nk+i] = w[encRoundOffset+i*Nk+j];
        }

        // Column-wise XOR of state encryption key
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                state[j][i] = (byte) (state[j][i] ^ roundKey[i]);
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
                state[i][j] = (byte) Rijndael.sbox[state[i][j] & 0xFF];
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
     * Mix one column by by considering it as a polynomial and performing
     * operations in the Galois field (2^8).
     */
    private static void mixColumns() {
        for (int i = 0; i < Nb; ++i) {
            // Store temporary column for operations
            byte[] temp = new byte[Nb];
            for (int j = 0; j < Nb; ++j) {
                temp[j] = state[j][i];
            }
            // XOR is addition in this field
            state[0][i] = (byte) (galoisMult(temp[0], (byte) 2) ^ galoisMult(temp[1], (byte) 3) ^
                                  galoisMult(temp[2], (byte) 1) ^ galoisMult(temp[3], (byte) 1));
            state[1][i] = (byte) (galoisMult(temp[0], (byte) 1) ^ galoisMult(temp[1], (byte) 2) ^
                                  galoisMult(temp[2], (byte) 3) ^ galoisMult(temp[3], (byte) 1));
            state[2][i] = (byte) (galoisMult(temp[0], (byte) 1) ^ galoisMult(temp[1], (byte) 1) ^
                                  galoisMult(temp[2], (byte) 2) ^ galoisMult(temp[3], (byte) 3));
            state[3][i] = (byte) (galoisMult(temp[0], (byte) 3) ^ galoisMult(temp[1], (byte) 1) ^
                                  galoisMult(temp[2], (byte) 1) ^ galoisMult(temp[3], (byte) 2));
        }
    }

    /**
     * Encrypt the current state.
     */
    private static void encryptState() {
        int offset = Nb * Nb;
        for (int i = 0; i < Nb; ++i) {
            addRoundKey(0, offset); // Initial key round

            for (int j = 1; j < Nr; ++j) {
                subBytes();
                shiftRows();
                mixColumns();
                addRoundKey(j, offset);
            }

            // Leave out MixColumns for final round
            subBytes();
            shiftRows();
            addRoundKey(Nr, offset);
        }
    }

    /**
     * Print the encrypted state to stdout.
     */
    private static void outputState() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Nb; ++i) {
            for (int j = 0; j < Nb; ++j) {
                // System.out.write(state[j][i]);
                sb.append(String.format("%02X ", state[j][i])); // TODO
            }
        }
        // System.out.flush();
        System.out.println("Result:");
        System.out.println(sb);
    }

    /**
     * Iteratively encrypt blocks.
     */
    private static void encryptBlocks() {
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
        // TODO
        StringBuilder sb = new StringBuilder();
        System.out.println("Plain text:");
        for (int i = 0; i < textLength; ++i) sb.append(String.format("%02X ", plainText[i]));
        System.out.println(sb);
        // Pad plain text if necessary
        padPlainText();

        // byte[] key = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; // TODO

        // Expand encryption key
        Rijndael.expandKeys(key, w, LENGTH_STATE, LENGTH_KEY, LENGTH_EXP_KEY);

        // TODO
        sb = new StringBuilder();
        System.out.println("Key:");
        for (byte b : key) sb.append(String.format("%02X ", b));
        System.out.println(sb);

        // Start encryption
        encryptBlocks();
    }
}
