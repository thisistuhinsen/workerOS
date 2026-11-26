package io.github.thisistuhinsen.workerhandoff;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Objects;

import static java.lang.foreign.ValueLayout.*;

/** A read-only interface to a validated, privately duplicated Linux ABI v1 binding. */
public final class InheritedReader implements AutoCloseable {
    private int fd;

    private InheritedReader(int fd) {
        this.fd = fd;
    }

    /** Borrow the launcher's original until duplication completes. Close the returned handle. */
    public static InheritedReader open(String binding) throws IOException {
        String arch = System.getProperty("os.arch", "");
        if (!"Linux".equals(System.getProperty("os.name")) || ADDRESS.byteSize() != 8
                || !("amd64".equals(arch) || "x86_64".equals(arch) || "aarch64".equals(arch))) {
            throw new UnsupportedOperationException("Linux x64 or ARM64 required");
        }
        if (binding == null || !binding.matches("[A-Z][A-Z0-9_]*")) {
            throw new IllegalArgumentException("Expected uppercase ASCII binding");
        }
        if (!"1".equals(System.getenv("WORKER_HANDOFF_ABI"))) {
            throw new IllegalArgumentException("Expected worker-handoff ABI 1");
        }
        long raw = decimal("FD", binding);
        if (raw < 3 || raw > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("FD outside the inherited descriptor range");
        }
        long device = decimal("DEV", binding);
        long inode = decimal("INO", binding);
        String access = System.getenv("WORKER_HANDOFF_ACCESS_" + binding);
        if (!"read".equals(access) && !"read-write".equals(access)) {
            throw new IllegalArgumentException("Binding requires read or read-write access");
        }

        // Linux F_DUPFD_CLOEXEC pins this open file description for the handle's lifetime.
        int copy = Native.fcntl((int) raw, 1030, 3);
        InheritedReader reader = new InheritedReader(copy);
        try {
            int flags = Native.fcntl(copy, 3, 0);  // F_GETFL
            int expectedMode = access.equals("read") ? 0 : 2;
            if ((flags & 010000000) != 0 || (flags & 3) != expectedMode) {
                throw new IOException("Inherited descriptor access mismatch or O_PATH");
            }
            Path table = Path.of("/proc/self/fd");
            if (!Files.getFileStore(table).type().equals("proc")) {
                throw new IOException("Descriptor inspection requires Linux procfs");
            }
            Map<String, Object> facts = Files.readAttributes(table.resolve(Integer.toString(copy)),
                    "unix:mode,dev,ino");
            if (((int) facts.get("mode") & 0170000) != 0100000
                    || (long) facts.get("dev") != device || (long) facts.get("ino") != inode) {
                throw new IOException("Inherited descriptor is not the declared regular file");
            }
            return reader;
        } catch (IOException | RuntimeException | Error failure) {
            try {
                reader.close();
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
            throw failure;
        }
    }

    private static long decimal(String field, String binding) {
        String key = "WORKER_HANDOFF_" + field + "_" + binding;
        String text = System.getenv(key);
        if (text == null || text.length() > 20 || !text.matches("0|[1-9][0-9]*")) {
            throw new IllegalArgumentException("Invalid unsigned decimal in " + key);
        }
        return Long.parseUnsignedLong(text);
    }

    /** Read at offset without moving the shared file offset. Returns -1 at EOF, or 0 for an empty buffer. */
    public synchronized int readAt(long offset, byte[] destination) throws IOException {
        if (fd < 0) throw new IOException("Reader is closed");
        if (offset < 0) throw new IllegalArgumentException("Negative offset");
        Objects.requireNonNull(destination);
        if (destination.length == 0) return 0;
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment data = arena.allocate(destination.length);
            MemorySegment state = arena.allocate(Linker.Option.captureStateLayout());
            long count;
            do {
                count = Native.pread(state, fd, data, destination.length, offset);
            } while (count < 0 && state.get(JAVA_INT, Native.ERRNO) == 4);  // EINTR
            if (count < 0) throw new IOException("pread failed, errno " + state.get(JAVA_INT, Native.ERRNO));
            if (count == 0) return -1;
            MemorySegment.copy(data, JAVA_BYTE, 0, destination, 0, (int) count);
            return (int) count;
        }
    }

    /** Close the private duplicate once. The original descriptor remains the caller's responsibility. */
    @Override
    public synchronized void close() throws IOException {
        if (fd < 0) return;
        int copy = fd;
        fd = -1;
        Native.close(copy);
    }

    private static final class Native {
        private static final Linker LINKER = Linker.nativeLinker();
        private static final long ERRNO = Linker.Option.captureStateLayout()
                .byteOffset(MemoryLayout.PathElement.groupElement("errno"));
        private static final MethodHandle FCNTL = LINKER.downcallHandle(
                LINKER.defaultLookup().find("fcntl").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT), Linker.Option.firstVariadicArg(2));
        private static final MethodHandle PREAD = LINKER.downcallHandle(
                LINKER.defaultLookup().find("pread").orElseThrow(),
                FunctionDescriptor.of(JAVA_LONG, JAVA_INT, ADDRESS, JAVA_LONG, JAVA_LONG),
                Linker.Option.captureCallState("errno"));
        private static final MethodHandle CLOSE = LINKER.downcallHandle(
                LINKER.defaultLookup().find("close").orElseThrow(), FunctionDescriptor.of(JAVA_INT, JAVA_INT));

        static int fcntl(int fd, int command, int arg) throws IOException {
            int result;
            try {
                result = (int) FCNTL.invokeExact(fd, command, arg);
            } catch (Throwable failure) {
                throw new IOException("Cannot invoke fcntl", failure);
            }
            if (result < 0) throw new IOException("fcntl failed for command " + command);
            return result;
        }

        static long pread(MemorySegment state, int fd, MemorySegment data, long length, long offset)
                throws IOException {
            try {
                return (long) PREAD.invokeExact(state, fd, data, length, offset);
            } catch (Throwable failure) {
                throw new IOException("Cannot invoke pread", failure);
            }
        }

        static void close(int fd) throws IOException {
            int result;
            try {
                result = (int) CLOSE.invokeExact(fd);
            } catch (Throwable failure) {
                throw new IOException("Cannot invoke close", failure);
            }
            if (result != 0) throw new IOException("close failed");
        }
    }
}
