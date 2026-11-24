package org.eclipse.tracecompass.helloworld.ui.views;

import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.tracecompass.analysis.graph.core.criticalpath.AbstractCriticalPathModule;
import org.eclipse.tracecompass.analysis.graph.core.criticalpath.OSCriticalPathModule;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfGraph;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsExecutionGraph;
import org.eclipse.tracecompass.analysis.os.linux.core.execution.graph.OsWorker;
import org.eclipse.tracecompass.tmf.core.dataprovider.DataProviderManager;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceUtils;

import com.google.gson.JsonObject;

/**
 * The Critical Path output of a Trace Server client (the VS Code trace viewer), following a
 * thread. No UI: the server-side counterpart of the Eclipse chat's {@code showCriticalPath}.
 *
 * <p>The Critical Path data provider reads whichever critical-path analysis last announced its
 * start on the trace ({@code OSCriticalPathDataProviderFactory}), and the TSP has no call that
 * names the thread to follow (Eclipse's "Follow thread"). So this starts one for the thread and
 * the plan's range, on the server's own experiment (the one the viewer shows), after dropping
 * the experiment's cached Critical Path provider: the viewer's next request binds to it.</p>
 *
 * <p>Like Eclipse's, the analyses are kept, never disposed: disposing clears the graph, and a
 * provider still bound to it would wait forever. Each covers one short range.</p>
 */
final class ServerCriticalPath {

    /** The output descriptor (the Trace Server does not list this output: it needs a thread). */
    static JsonObject descriptor() {
        JsonObject descriptor = new JsonObject();
        descriptor.addProperty("id", AnswerPipeline.CRITICAL_PATH_PROVIDER_ID);
        descriptor.addProperty("name", "Critical Path");
        descriptor.addProperty("description",
                "The critical path of the followed thread: what it waited on, and what that waited on, over the range");
        descriptor.addProperty("type", "TIME_GRAPH");
        return descriptor;
    }

    private ServerCriticalPath() {
    }

    /**
     * Follows {@code tid} on {@code trace} over [{@code start}, {@code end}] (the whole trace
     * when the range covers it) and announces it to the Critical Path provider.
     *
     * @return null when the critical path is ready to show, otherwise why not
     */
    static @Nullable String follow(ITmfTrace trace, int tid, long start, long end) {
        OsExecutionGraph graphModule = TmfTraceUtils.getAnalysisModuleOfClass(trace, OsExecutionGraph.class,
                OsExecutionGraph.ANALYSIS_ID);
        if (graphModule == null) {
            return "the trace has no execution graph analysis";
        }
        graphModule.schedule();
        if (!graphModule.waitForCompletion()) {
            return "the execution graph did not complete";
        }
        ITmfGraph graph = graphModule.getTmfGraph();
        OsWorker worker = graph == null ? null : AnswerPipeline.findOsWorker(graph, tid);
        if (worker == null) {
            return "TID " + tid + " is not in the execution graph";
        }
        OSCriticalPathModule module = new OSCriticalPathModule(graphModule, worker);
        long traceStart = trace.getStartTime().toNanos();
        long traceEnd = trace.getEndTime().toNanos();
        if (start > traceStart || end < traceEnd) {
            // The path covers exactly the selected range (as in Eclipse; the padding is only for the zoom).
            module.setParameter(AbstractCriticalPathModule.PARAM_WINDOW_START, start);
            module.setParameter(AbstractCriticalPathModule.PARAM_WINDOW_END, end + 2);
        }
        try {
            module.setTrace(trace);
        } catch (TmfAnalysisException exception) {
            return exception.getMessage();
        }
        DataProviderManager.getInstance().removeDataProvider(trace, AnswerPipeline.CRITICAL_PATH_PROVIDER_ID);
        OSCriticalPathModule previous = AnswerPipeline.sViewCriticalPath;
        /* The pipeline re-announces this one after its own temporary analyses (restoreCriticalPathBinding). */
        AnswerPipeline.sViewCriticalPath = module;
        if (previous != null) {
            AnswerPipeline.sRetiredViewCriticalPaths.add(previous);
        }
        // Starting it announces it to the provider factory.
        module.schedule();
        if (!module.waitForCompletion()) {
            return "the critical path analysis did not complete";
        }
        return null;
    }
}
