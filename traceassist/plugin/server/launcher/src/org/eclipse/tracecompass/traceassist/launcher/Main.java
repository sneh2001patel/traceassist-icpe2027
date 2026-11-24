package org.eclipse.tracecompass.traceassist.launcher;

import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

/**
 * The executable TraceAssist jar: installs the TraceAssist bundle in a Trace Compass Trace
 * Server and starts the server with the user's own OpenAI API key.
 *
 * <pre>
 * java -jar traceassist-server.jar start   --server &lt;trace-server folder&gt; [options]
 * java -jar traceassist-server.jar install --server &lt;trace-server folder&gt; [--port N]
 * </pre>
 *
 * The key is taken from {@code --api-key-file}, else the {@code OPENAI_API_KEY} environment
 * variable, else asked for (hidden input). It is passed only to the server process's
 * environment: never written to disk, never printed.
 *
 * Needs Java 11 or later to run; the Trace Server runs on its own bundled Java.
 */
public final class Main {

    private static final String BUNDLE_NAME = "org.eclipse.tracecompass.traceassist.server";
    private static final String GRAPH_BUNDLE = "org.eclipse.tracecompass.analysis.graph.core";
    private static final String BACKUP_FOLDER = "backup-before-traceassist";

    private Main() {
    }

    public static void main(String[] args) {
        try {
            System.exit(run(args));
        } catch (UsageException exception) {
            System.err.println("error: " + exception.getMessage());
            System.err.println();
            usage();
            System.exit(2);
        } catch (Exception exception) {
            System.err.println("error: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void usage() {
        System.err.println(String.join("\n",
                "TraceAssist for the Trace Compass Trace Server",
                "",
                "Usage:",
                "  java -jar traceassist-server.jar start   --server <trace-server folder> [options]",
                "  java -jar traceassist-server.jar install --server <trace-server folder> [--port N] [--force]",
                "",
                "start: installs TraceAssist (if needed), asks for your OpenAI API key, and runs the server.",
                "install: only installs it (the bundle, its settings, and the critical-path patch).",
                "",
                "Options:",
                "  --server DIR         the Trace Server folder (holds tracecompass-server and plugins/)",
                "  --port N             TraceAssist endpoint port (default 8092)",
                "  --tsp-port N         Trace Server (TSP) port (default 8081)",
                "  --memory SIZE        Trace Server Java heap, e.g. 8g (default 4g)",
                "  --workspace DIR      where the Trace Server keeps its data (default ~/.tracecompass-webapp)",
                "  --api-key-file FILE  read the OpenAI API key from FILE (first line)",
                "  --ask-key            always ask for the key, even if OPENAI_API_KEY is set",
                "  --skip-key-check     do not check the key with OpenAI before starting",
                "  --force              install even if the Trace Server's version was not tested",
                "",
                "The API key goes only to the server process: it is never saved or printed."));
    }

    /** A wrong command line. */
    private static final class UsageException extends Exception {
        private static final long serialVersionUID = 1L;

        UsageException(String message) {
            super(message);
        }
    }

    private static int run(String[] args) throws Exception {
        if (args.length == 0 || Arrays.asList("-h", "--help", "help").contains(args[0])) {
            usage();
            return args.length == 0 ? 2 : 0;
        }
        String command = args[0];
        Map<String, String> options = new LinkedHashMap<>();
        Set<String> flags = new HashSet<>(Arrays.asList("--ask-key", "--skip-key-check", "--force"));
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if (flags.contains(arg)) {
                options.put(arg, "true");
            } else if (arg.startsWith("--") && i + 1 < args.length) {
                options.put(arg, args[++i]);
            } else {
                throw new UsageException("unexpected argument " + arg);
            }
        }
        for (String key : options.keySet()) {
            if (!flags.contains(key) && !Arrays.asList("--server", "--port", "--tsp-port", "--memory", "--workspace", "--api-key-file").contains(key)) {
                throw new UsageException("unknown option " + key);
            }
        }
        String server = options.get("--server");
        if (server == null) {
            throw new UsageException("--server <trace-server folder> is required");
        }
        Path serverDir = Paths.get(server).toAbsolutePath().normalize();
        int port = intOption(options, "--port", 8092);
        int tspPort = intOption(options, "--tsp-port", 8081);
        boolean force = options.containsKey("--force");

        switch (command) {
        case "install":
            install(serverDir, port, force);
            return 0;
        case "start":
            String apiKey = apiKey(options);
            if (!options.containsKey("--skip-key-check")) {
                checkKey(apiKey);
            }
            install(serverDir, port, force);
            return start(serverDir, port, tspPort, options.getOrDefault("--memory", "4g"), options.get("--workspace"), apiKey);
        default:
            throw new UsageException("unknown command " + command + " (start or install)");
        }
    }

    private static int intOption(Map<String, String> options, String name, int fallback) throws UsageException {
        String value = options.get(name);
        if (value == null) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException exception) {
            throw new UsageException(name + " must be a number");
        }
    }

    // --- The API key ------------------------------------------------------------------------

    private static String apiKey(Map<String, String> options) throws IOException {
        String file = options.get("--api-key-file");
        String key;
        String from;
        if (file != null) {
            List<String> lines = Files.readAllLines(Paths.get(file), StandardCharsets.UTF_8);
            key = lines.isEmpty() ? "" : lines.get(0).trim();
            from = "the key file";
        } else if (!options.containsKey("--ask-key") && System.getenv("OPENAI_API_KEY") != null
                && !System.getenv("OPENAI_API_KEY").isBlank()) {
            key = System.getenv("OPENAI_API_KEY").trim();
            from = "OPENAI_API_KEY in your environment";
        } else {
            Console console = System.console();
            if (console == null) {
                throw new IOException("no terminal to ask for the API key: set OPENAI_API_KEY or use --api-key-file");
            }
            char[] typed = console.readPassword("OpenAI API key (input hidden): ");
            key = typed == null ? "" : new String(typed).trim();
            if (typed != null) {
                Arrays.fill(typed, ' ');
            }
            from = "what you typed";
        }
        if (key.isEmpty()) {
            throw new IOException("no API key: TraceAssist needs one to answer questions");
        }
        System.out.println("Using the OpenAI API key from " + from + " (" + masked(key) + ").");
        return key;
    }

    /** "sk-…abcd": enough to tell keys apart, never the key. */
    private static String masked(String key) {
        String prefix = key.startsWith("sk-") ? "sk-" : "";
        return prefix + "…" + (key.length() > 8 ? key.substring(key.length() - 4) : "");
    }

    /** Asks OpenAI whether the key is accepted (it is only ever sent to OpenAI). */
    private static void checkKey(String apiKey) throws IOException {
        HttpURLConnection connection = (HttpURLConnection) new URL("https://api.openai.com/v1/models").openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(15_000);
        connection.setRequestProperty("Authorization", "Bearer " + apiKey);
        int status;
        try {
            status = connection.getResponseCode();
        } catch (IOException exception) {
            System.out.println("Could not reach OpenAI to check the key (" + exception.getMessage() + "); starting anyway.");
            return;
        } finally {
            connection.disconnect();
        }
        if (status == 401 || status == 403) {
            throw new IOException("OpenAI rejected the API key (HTTP " + status + ")");
        }
        System.out.println(status == 200 ? "OpenAI accepted the key." : "OpenAI answered HTTP " + status + " to the key check; starting anyway.");
    }

    // --- Install ------------------------------------------------------------------------------

    private static void install(Path serverDir, int port, boolean force) throws IOException {
        Path plugins = serverDir.resolve("plugins");
        Path config = serverDir.resolve("configuration").resolve("config.ini");
        if (!Files.isDirectory(plugins) || !Files.isRegularFile(config)) {
            throw new IOException(serverDir + " is not a Trace Compass Trace Server (no plugins/ or configuration/config.ini)");
        }
        Properties built = new Properties();
        try (InputStream in = resource("traceassist.properties")) {
            built.load(in);
        }
        String bundleFile = built.getProperty("bundle.file");
        String graphVersion = built.getProperty("graph.version");
        Path backup = serverDir.resolve(BACKUP_FOLDER);

        // 1. The critical-path patch: the window parameters TraceAssist sets on critical-path analyses.
        Path graphJar = newest(plugins, GRAPH_BUNDLE);
        if (graphJar == null) {
            throw new IOException("no " + GRAPH_BUNDLE + " in " + plugins);
        }
        String version = graphJar.getFileName().toString().replaceFirst("^" + Pattern.quote(GRAPH_BUNDLE) + "_", "").replaceFirst("\\.jar$", "");
        if (!sameMinor(version, graphVersion)) {
            String message = "this Trace Server has " + GRAPH_BUNDLE + " " + version + "; TraceAssist was built for "
                    + graphVersion + ". Its critical-path patch may not fit.";
            if (!force) {
                throw new IOException(message + " Use --force to install anyway.");
            }
            System.out.println("warning: " + message);
        }
        Map<String, byte[]> patch = patchClasses(built);
        Files.createDirectories(backup);
        Path original = backup.resolve(graphJar.getFileName());
        if (!Files.exists(original)) {
            Files.copy(graphJar, original);
        }
        if (!hasClasses(graphJar, patch)) {
            Path patched = graphJar.resolveSibling(graphJar.getFileName() + ".traceassist.tmp");
            writePatchedJar(original, patched, patch);
            Files.move(patched, graphJar, StandardCopyOption.REPLACE_EXISTING);
            System.out.println("Patched " + graphJar.getFileName() + " (original in " + BACKUP_FOLDER + "/)");
        }

        // 2. The bundle.
        for (Path old : list(plugins, BUNDLE_NAME)) {
            if (!old.getFileName().toString().equals(bundleFile)) {
                Files.delete(old);
            }
        }
        Path target = plugins.resolve(bundleFile);
        byte[] bundle;
        try (InputStream in = resource("bundle/" + bundleFile)) {
            bundle = readAll(in);
        }
        if (!Files.exists(target) || !Arrays.equals(Files.readAllBytes(target), bundle)) {
            Files.write(target, bundle);
            System.out.println("Installed " + bundleFile);
        }

        // 3. config.ini: start the bundle with the server; its port.
        Path configBackup = backup.resolve("config.ini");
        if (!Files.exists(configBackup)) {
            Files.copy(config, configBackup);
        }
        String text = new String(Files.readAllBytes(config), StandardCharsets.ISO_8859_1);
        String updated = text.replaceAll(",reference\\\\:file\\\\:" + Pattern.quote(BUNDLE_NAME) + "_[^,\\r\\n]*", "");
        Matcher bundles = Pattern.compile("(?m)^(osgi\\.bundles=.*)$").matcher(updated);
        if (!bundles.find()) {
            throw new IOException(config + " has no osgi.bundles line");
        }
        updated = updated.substring(0, bundles.end()) + ",reference\\:file\\:" + bundleFile + "@4\\:start"
                + updated.substring(bundles.end());
        String portLine = "traceassist.port=" + port;
        if (Pattern.compile("(?m)^traceassist\\.port=").matcher(updated).find()) {
            updated = updated.replaceAll("(?m)^traceassist\\.port=.*$", portLine);
        } else {
            updated = updated.replaceAll("\\s*$", "") + "\n" + portLine + "\n";
        }
        if (!updated.equals(text)) {
            Files.write(config, updated.getBytes(StandardCharsets.ISO_8859_1));
            System.out.println("Updated configuration/config.ini (original in " + BACKUP_FOLDER + "/)");
        }
        System.out.println("TraceAssist is installed in " + serverDir);
    }

    private static boolean sameMinor(String version, String expected) {
        String[] a = version.split("\\.");
        String[] b = expected.split("\\.");
        return a.length >= 2 && b.length >= 2 && a[0].equals(b[0]) && a[1].equals(b[1]);
    }

    /** The patched classes packaged in this jar, by entry name. */
    private static Map<String, byte[]> patchClasses(Properties built) throws IOException {
        Map<String, byte[]> classes = new LinkedHashMap<>();
        for (String entry : built.getProperty("patch.classes").split(",")) {
            try (InputStream in = resource("patch/" + entry.trim())) {
                classes.put(entry.trim(), readAll(in));
            }
        }
        return classes;
    }

    private static boolean hasClasses(Path jar, Map<String, byte[]> classes) throws IOException {
        Map<String, byte[]> found = new LinkedHashMap<>();
        try (ZipInputStream zip = new ZipInputStream(Files.newInputStream(jar))) {
            for (ZipEntry entry; (entry = zip.getNextEntry()) != null;) {
                if (classes.containsKey(entry.getName())) {
                    found.put(entry.getName(), readAll(zip));
                }
            }
        }
        for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
            if (!Arrays.equals(entry.getValue(), found.get(entry.getKey()))) {
                return false;
            }
        }
        return true;
    }

    /**
     * The original jar with the patched classes replaced. Its signature files are dropped: the
     * jar is no longer signed (Equinox does not check signatures by default).
     */
    private static void writePatchedJar(Path original, Path target, Map<String, byte[]> classes) throws IOException {
        try (ZipInputStream in = new ZipInputStream(Files.newInputStream(original));
                ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(target))) {
            for (ZipEntry entry; (entry = in.getNextEntry()) != null;) {
                String name = entry.getName();
                if (classes.containsKey(name) || name.matches("META-INF/[^/]+\\.(SF|RSA|DSA|EC)")) {
                    continue;
                }
                out.putNextEntry(new ZipEntry(name));
                copy(in, out);
                out.closeEntry();
            }
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                out.putNextEntry(new ZipEntry(entry.getKey()));
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
    }

    // --- Start --------------------------------------------------------------------------------

    private static int start(Path serverDir, int port, int tspPort, String memory, String workspace, String apiKey)
            throws Exception {
        Path executable = serverDir.resolve(isWindows() ? "tracecompass-server.exe" : "tracecompass-server");
        if (!Files.isRegularFile(executable)) {
            throw new IOException("no " + executable.getFileName() + " in " + serverDir);
        }
        for (int busy : new int[] { tspPort, port }) {
            if (answers("http://127.0.0.1:" + busy + "/")) {
                throw new IOException("port " + busy + " is already in use (is a Trace Server already running?)");
            }
        }
        List<String> command = new ArrayList<>(Arrays.asList(executable.toString(), "-clean"));
        if (workspace != null) {
            Path data = Paths.get(workspace).toAbsolutePath();
            Files.createDirectories(data);
            command.addAll(Arrays.asList("-data", data.toString()));
        }
        command.addAll(Arrays.asList("-vmargs", "-Dtraceserver.port=" + tspPort, "-Xmx" + memory));
        ProcessBuilder builder = new ProcessBuilder(command).directory(serverDir.toFile()).inheritIO();
        builder.environment().put("OPENAI_API_KEY", apiKey); // the server process only
        System.out.println("Starting the Trace Server (TSP on " + tspPort + ", TraceAssist on " + port + "); Ctrl+C stops it.");
        Process process = builder.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (process.isAlive()) {
                process.destroy();
            }
        }));
        String tsp = "http://127.0.0.1:" + tspPort + "/tsp/api/health";
        String traceAssist = "http://127.0.0.1:" + port + "/test/health";
        for (int i = 0; i < 180 && process.isAlive(); i++) {
            if (answers(tsp) && answers(traceAssist)) {
                System.out.println();
                System.out.println("Ready. In VS Code, point the Trace Viewer at http://localhost:" + tspPort
                        + " and TraceAssist at http://127.0.0.1:" + port + ".");
                break;
            }
            Thread.sleep(1000);
        }
        return process.waitFor();
    }

    private static boolean answers(String url) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setConnectTimeout(1000);
            connection.setReadTimeout(2000);
            int status = connection.getResponseCode();
            connection.disconnect();
            return status > 0;
        } catch (IOException exception) {
            return false;
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase().contains("win");
    }

    // --- Helpers ------------------------------------------------------------------------------

    private static InputStream resource(String name) throws IOException {
        InputStream in = Main.class.getResourceAsStream("/" + name);
        if (in == null) {
            throw new IOException("this jar is incomplete: no " + name);
        }
        return in;
    }

    private static List<Path> list(Path folder, String bundle) throws IOException {
        List<Path> found = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(folder, bundle + "_*.jar")) {
            stream.forEach(found::add);
        }
        found.sort(null);
        return found;
    }

    private static Path newest(Path folder, String bundle) throws IOException {
        List<Path> found = list(folder, bundle);
        return found.isEmpty() ? null : found.get(found.size() - 1);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        copy(in, bytes);
        return bytes.toByteArray();
    }

    private static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[64 * 1024];
        for (int n; (n = in.read(buffer)) > 0;) {
            out.write(buffer, 0, n);
        }
    }
}
