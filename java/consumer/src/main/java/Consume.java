import io.github.thisistuhinsen.workeros.InheritedReader;
import java.io.IOException;
import java.util.Arrays;

public class Consume {
    public static void main(String[] args) throws IOException {
        if (args.length > 0) {
            try (var ignored = InheritedReader.open(args[0])) {
                throw new AssertionError("Accepted invalid binding");
            } catch (IllegalArgumentException | IOException expected) {
                return;
            }
        }
        InheritedReader first = InheritedReader.open("INPUT");
        try (first) {
            byte[] pair = new byte[2];
            if (first.readAt(1, pair) != 2 || !Arrays.equals(pair, new byte[]{'o', 'r'})) {
                throw new AssertionError("Wrong positional read");
            }
            if (first.readAt(6, pair) != -1 || first.readAt(0, new byte[0]) != 0) {
                throw new AssertionError("Wrong end-of-file or empty read");
            }
        }
        first.close();
        try {
            first.readAt(0, new byte[1]);
            throw new AssertionError("Read succeeded after close");
        } catch (IOException expected) {
            // Closing the private handle prevents further reads.
        }
        try (var next = InheritedReader.open("INPUT")) {
            byte[] b = new byte[1];
            if (next.readAt(0, b) != 1 || b[0] != 'W') throw new AssertionError("Original lost");
        }
    }
}
