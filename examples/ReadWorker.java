import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;

public class ReadWorker {
    public static void main(String[] args) throws Throwable {
        String value = System.getenv("WORKER_HANDOFF_FD_INPUT");
        if (!"1".equals(System.getenv("WORKER_HANDOFF_ABI")) || value == null) {
            System.exit(2);
        }

        final int fd;
        try {
            fd = Integer.parseInt(value);
            if (fd < 3 || !Integer.toString(fd).equals(value)) System.exit(2);
        } catch (NumberFormatException ex) {
            System.exit(2);
            return;
        }

        Linker linker = Linker.nativeLinker();
        MethodHandle pread = linker.downcallHandle(
            linker.defaultLookup().find("pread").orElseThrow(),
            FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG, JAVA_LONG)
        );
        MethodHandle close = linker.downcallHandle(
            linker.defaultLookup().find("close").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT)
        );

        boolean ok;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment buffer = arena.allocate(1);
            long count = (long) pread.invokeExact(fd, buffer, 1L, 0L);
            ok = count == 1 && buffer.get(JAVA_BYTE, 0) == (byte) 'W';
        } finally {
            int result = (int) close.invokeExact(fd);
            if (result != 0) throw new IllegalStateException("close failed");
        }
        if (!ok) System.exit(1);
    }
}
