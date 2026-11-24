package org.eclipse.tracecompass.helloworld.ui.views;

import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

/**
 * The TraceAssist bundle in the Trace Server: starts the question endpoint
 * ({@code POST /test/context}, the same request and response as the Eclipse
 * plug-in's test endpoint) when the server starts.
 *
 * Settings (framework properties in the server's configuration/config.ini, or
 * -D system properties):
 * <ul>
 * <li>{@value #PORT_PROPERTY}: the port on 127.0.0.1 (default {@value #DEFAULT_PORT});</li>
 * <li>{@value AiSkill#HOME_PROPERTY}: the folder the skills and view cards are read from
 * (the plug-in's project folder, so an edited skill applies to both); without it, the copy
 * packaged in the bundle.</li>
 * </ul>
 * The AI skills need {@code OPENAI_API_KEY} in the server's environment.
 */
public class ServerActivator implements BundleActivator {

    static final String PORT_PROPERTY = "traceassist.port";
    static final int DEFAULT_PORT = 8092;

    /** How long to wait for the Trace Server to set its workspace before giving up. */
    private static final long STARTUP_WAIT_MS = 5 * 60 * 1000L;

    private volatile AnswerPipeline.AgentTestServer server;
    private volatile boolean stopping;

    /**
     * Starts the endpoint once the Trace Server is up. Nothing from Trace Compass may load
     * before the server application has set the instance (workspace) location: activating
     * tmf.core earlier fails it for good, and the server with it. So this only starts a
     * thread, which waits for the location and then creates the pipeline.
     */
    @Override
    public void start(BundleContext context) {
        String home = context.getProperty(AiSkill.HOME_PROPERTY);
        if (home != null && !home.isBlank() && System.getProperty(AiSkill.HOME_PROPERTY) == null) {
            System.setProperty(AiSkill.HOME_PROPERTY, home.trim());
        }
        String portText = context.getProperty(PORT_PROPERTY);
        int port = portText == null || portText.isBlank() ? DEFAULT_PORT : Integer.parseInt(portText.trim());
        Thread starter = new Thread(() -> startWhenReady(port), "traceassist-start");
        starter.setDaemon(true);
        starter.start();
    }

    private void startWhenReady(int port) {
        long deadline = System.currentTimeMillis() + STARTUP_WAIT_MS;
        try {
            while (!stopping && !instanceLocationSet()) {
                if (System.currentTimeMillis() > deadline) {
                    System.err.println("TraceAssist endpoint not started: the Trace Server set no workspace location");
                    return;
                }
                Thread.sleep(500);
            }
            if (stopping) {
                return;
            }
            server = AnswerPipeline.AgentTestServer.start(new AnswerPipeline(), port);
            String skills = System.getProperty(AiSkill.HOME_PROPERTY);
            System.out.println("TraceAssist endpoint listening on http://127.0.0.1:" + port
                    + " (skills from " + (skills == null ? "the bundle" : skills) + ", OpenAI key "
                    + (System.getenv("OPENAI_API_KEY") == null ? "MISSING" : "set") + ")");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
        } catch (Exception | LinkageError exception) {
            System.err.println("TraceAssist endpoint not started: " + exception);
            exception.printStackTrace();
        }
    }

    private static boolean instanceLocationSet() {
        org.eclipse.osgi.service.datalocation.Location location = org.eclipse.core.runtime.Platform.getInstanceLocation();
        return location != null && location.isSet();
    }

    @Override
    public void stop(BundleContext context) {
        stopping = true;
        AnswerPipeline.AgentTestServer running = server;
        if (running != null) {
            running.stop();
            server = null;
        }
    }
}
