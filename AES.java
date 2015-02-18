/**
 * A 128-bit implementation of the AES cipher (encryption only).
 * Reads a binary file from stdin and outputs the result on stdout.
 * Spec: http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
 */
import java.io.DataInputStream;
import java.util.ArrayList;


public class AES {
    private static final int KEY_LENGTH = 16; // Key length in bytes

    public static void main(String[] args) {
        ArrayList<Byte> key       = new ArrayList<Byte>();
        ArrayList<Byte> plainText = new ArrayList<Byte>();
        StringBuilder sb          = new StringBuilder();

        // Read the bytes from stdin
        DataInputStream dis;
        try {
            dis = new DataInputStream(System.in);
            for (int i = 0; dis.available() > 0 && i < KEY_LENGTH; ++i) {
                key.add(dis.readByte());
            }
            while (dis.available() > 0) {
                plainText.add(dis.readByte());
            }
            dis.close();
        } catch (Exception e){
            e.printStackTrace();
        }

        // Print key and data
        for (byte b : key)
            sb.append(String.format("%02X ", b));
        System.out.println(sb);
        sb = new StringBuilder();
        for (byte b : plainText)
            sb.append(String.format("%02X ", b));
        System.out.println(sb);
    }
}
