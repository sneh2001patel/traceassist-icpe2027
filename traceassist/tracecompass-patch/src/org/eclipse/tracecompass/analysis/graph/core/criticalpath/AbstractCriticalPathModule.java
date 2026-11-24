/*******************************************************************************
 * Copyright (c) 2022, 2024 École Polytechnique de Montréal and others
 *
 * All rights reserved. This program and the accompanying materials are made
 * available under the terms of the Eclipse Public License 2.0 which
 * accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/

package org.eclipse.tracecompass.analysis.graph.core.criticalpath;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.eclipse.core.runtime.IProgressMonitor;
import org.eclipse.jdt.annotation.NonNull;
import org.eclipse.jdt.annotation.Nullable;
import org.eclipse.osgi.util.NLS;
import org.eclipse.tracecompass.analysis.graph.core.base.IGraphWorker;
import org.eclipse.tracecompass.analysis.graph.core.building.AbstractTmfGraphBuilderModule;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfEdge;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfGraph;
import org.eclipse.tracecompass.analysis.graph.core.graph.ITmfVertex;
import org.eclipse.tracecompass.analysis.graph.core.graph.WorkerSerializer;
import org.eclipse.tracecompass.common.core.NonNullUtils;
import org.eclipse.tracecompass.internal.analysis.graph.core.Activator;
import org.eclipse.tracecompass.internal.analysis.graph.core.criticalpath.Messages;
import org.eclipse.tracecompass.internal.analysis.graph.core.criticalpath.OSCriticalPathAlgorithm;
import org.eclipse.tracecompass.tmf.core.analysis.TmfAbstractAnalysisModule;
import org.eclipse.tracecompass.tmf.core.exceptions.TmfAnalysisException;
import org.eclipse.tracecompass.tmf.core.trace.ITmfTrace;
import org.eclipse.tracecompass.tmf.core.trace.TmfTraceManager;

import com.google.common.annotations.VisibleForTesting;

/**
 * Class to implement the critical path analysis
 *
 * @author Francis Giraldeau
 * @author Geneviève Bastien
 * @since 4.0
 */
public abstract class AbstractCriticalPathModule extends TmfAbstractAnalysisModule implements ICriticalPathProvider {

    /**
     * Analysis ID for this module
     * @since 5.0
     */
    public static final String ANALYSIS_ID = "org.eclipse.tracecompass.analysis.graph.core.criticalpath"; //$NON-NLS-1$

    /** Worker_id parameter name */
    public static final String PARAM_WORKER = "workerid"; //$NON-NLS-1$

    /**
     * Optional parameter: nanosecond timestamp to start the critical path
     * search from, instead of the worker's very first recorded vertex. When
     * unset (the default), behavior is unchanged from before this parameter
     * existed -- the search starts at the worker's head.
     *
     * This exists because {@link #executeAnalysis} otherwise always walks a
     * worker's *entire* recorded lifetime, which is wasted work when the
     * caller only cares about one short interval of a long-lived thread (the
     * common case on real, non-synthetic traces). The underlying algorithm
     * ({@link ICriticalPathAlgorithm#computeCriticalPath}) already accepts a
     * bounded start/end vertex; this parameter is what lets a caller reach
     * that capability without subclassing.
     *
     * @since 5.1
     */
    public static final String PARAM_WINDOW_START = "windowStartNs"; //$NON-NLS-1$

    /**
     * Optional parameter: nanosecond timestamp to stop the critical path
     * search at (exclusive), instead of running to the worker's natural end.
     * When unset (the default), behavior is unchanged -- the search runs
     * unbounded, as before this parameter existed. See
     * {@link #PARAM_WINDOW_START}.
     *
     * @since 5.1
     */
    public static final String PARAM_WINDOW_END = "windowEndNs"; //$NON-NLS-1$

    private static final int CRITICAL_PATH_GRAPH_VERSION = 1;

    private final AbstractTmfGraphBuilderModule fGraphModule;

    private volatile @Nullable ITmfGraph fCriticalPath;
    private volatile boolean fScheduleOnParameterChange = true;

    /**
     * Default constructor
     *
     * @param graph
     *            The graph module that will be used to calculate the critical
     *            path on
     * @since 1.1
     */
    public AbstractCriticalPathModule(AbstractTmfGraphBuilderModule graph) {
        addParameter(PARAM_WORKER);
        addParameter(PARAM_WINDOW_START);
        addParameter(PARAM_WINDOW_END);
        setId(ANALYSIS_ID);
        fGraphModule = graph;
    }

    /**
     * Constructor with the parameter. Can be used by benchmarks, to avoid that
     * setting the parameter causes the module to be schedule and run in a job
     * which keeps it in memory forever (and thus can cause OOME)
     *
     * @param graph
     *            The graph module that will be used to calculate the critical
     *            path on
     * @param worker
     *            The worker parameter to set
     * @since 3.1
     */
    @VisibleForTesting
    public AbstractCriticalPathModule(AbstractTmfGraphBuilderModule graph, IGraphWorker worker) {
        this(graph);
        fScheduleOnParameterChange = false;
        setParameter(PARAM_WORKER, worker);
    }

    @Override
    protected boolean executeAnalysis(final IProgressMonitor monitor) throws TmfAnalysisException {
        /* Get the worker id */
        Object workerObj = getParameter(PARAM_WORKER);
        if (workerObj == null) {
            return false;
        }
        if (!(workerObj instanceof IGraphWorker)) {
            throw new IllegalStateException("Worker parameter must be an IGraphWorker"); //$NON-NLS-1$
        }
        IGraphWorker worker = (IGraphWorker) workerObj;

        /* Get the graph */
        AbstractTmfGraphBuilderModule graphModule = fGraphModule;
        graphModule.schedule();

        monitor.setTaskName(NLS.bind(Messages.CriticalPathModule_waitingForGraph, graphModule.getName()));
        if (!graphModule.waitForCompletion(monitor)) {
            Activator.getInstance().logInfo("Critical path execution: graph building was cancelled.  Results may not be accurate."); //$NON-NLS-1$
            return false;
        }
        ITmfGraph graph = graphModule.getTmfGraph();
        if (graph == null) {
            throw new TmfAnalysisException("Critical Path analysis: graph " + graphModule.getName() + " is null"); //$NON-NLS-1$//$NON-NLS-2$
        }

        System.err.println("[CRITPATH-DEBUG] worker=" + worker //$NON-NLS-1$
                + " identityHash=" + System.identityHashCode(worker) //$NON-NLS-1$
                + " graphIdentityHash=" + System.identityHashCode(graph) //$NON-NLS-1$
                + " graph.getWorkers().contains(worker)=" + graph.getWorkers().contains(worker) //$NON-NLS-1$
                + " graph.getWorkers().size()=" + graph.getWorkers().size()); //$NON-NLS-1$

        Object windowStartObj = getParameter(PARAM_WINDOW_START);
        Object windowEndObj = getParameter(PARAM_WINDOW_END);
        boolean windowed = windowStartObj instanceof Long || windowEndObj instanceof Long;

        ITmfVertex head;
        if (windowStartObj instanceof Long) {
            /*
             * ITmfGraph#getVertexAt() is documented to return the vertex at
             * a timestamp "or the first vertex after" it, but testing
             * against critical-path-demo-long (a 180s worker lifetime,
             * window start ~10s before the tail -- well inside the
             * worker's real range, not before its head) showed it
             * returning null anyway. Its implementation
             * (HistoryTreeTmfGraph#getVertexAt) does a single indexed
             * point-query into the same historytree storage already
             * implicated in this project's other confirmed bugs
             * (critical_path_bug_report.md), so it is not trusted here.
             * Walking forward from the worker's own head via the same
             * edge-traversal primitive computeCriticalPath() itself
             * successfully uses is slower than a true indexed lookup would
             * be, but it is proven reliable (that traversal is exactly
             * what the unbounded call already does end to end), unlike
             * the indexed query.
             */
            head = findVertexAtOrAfter(
                    graph,
                    worker,
                    (Long) windowStartObj);
        } else {
            head = graph.getHead(worker);
        }

        System.err.println("[CRITPATH-DEBUG] windowed=" + windowed //$NON-NLS-1$
                + " windowStart=" + windowStartObj + " windowEnd=" + windowEndObj //$NON-NLS-1$ //$NON-NLS-2$
                + " head=" + head); //$NON-NLS-1$

        if (head == null) {
            /* Nothing happens with this worker, return an empty graph */
            ITmfGraph emptyGraph = createGraph();
            System.err.println("[CRITPATH-DEBUG] head was null -- createGraph() for empty result returned " //$NON-NLS-1$
                    + (emptyGraph == null ? "NULL (this is the bug: executeAnalysis() still returns true)" : "a valid empty graph")); //$NON-NLS-1$ //$NON-NLS-2$
            fCriticalPath = emptyGraph;
            return true;
        }

        ICriticalPathAlgorithm cp = getAlgorithm(graph);
        try {
            ITmfGraph criticalPath = createGraph();
            if (criticalPath == null) {
                System.err.println("[CRITPATH-DEBUG] createGraph() for the critical path result itself returned null (IOException creating the .ht file?)"); //$NON-NLS-1$
                return false;
            }
            // If the critical path has already been computed previously.
            // Skipped entirely when a time window is requested: the cached
            // graph's on-disk content carries no record of which window (if
            // any) it was built with, only which worker -- reusing it here
            // could silently hand back a differently-windowed (or unbounded)
            // result for the same worker. Always recomputing fresh for
            // windowed requests trades away this cache's reuse benefit in
            // exchange for never returning a stale-window result; the whole
            // point of a window is that it is meant to be cheaper to
            // (re)compute than the unbounded case anyway.
            if (!windowed && criticalPath.isDoneBuilding()) {
                ITmfVertex previousGraphHead = criticalPath.getHead();
                IGraphWorker previousGraphWorker = previousGraphHead == null ? null : criticalPath.getParentOf(previousGraphHead);
                IGraphWorker currentWorker = graph.getParentOf(head);
                // If it is the correct critical path
                boolean isSameWorker = previousGraphWorker != null && compareWorker(previousGraphWorker, currentWorker);

                /*
                 * isSameWorker (above) and the lookup below are two
                 * DIFFERENT "is this the same worker" checks that can
                 * disagree: isSameWorker compares field values
                 * (hostId + worker aspects), while getHead(worker)/
                 * getTail(worker) key into HistoryTreeTmfGraph's
                 * fWorkerAttrib map, populated from disk by readWorkers()
                 * using OsWorker's own equals()/hashCode() (HostThread-
                 * based). Testing (critical_path_bug_report.md's confirmed
                 * stale-cache bug) found isSameWorker=true while these
                 * calls still returned null -- i.e. compareWorker() saying
                 * "same worker" does not guarantee the cached graph can
                 * actually produce data for THIS worker object. Checking
                 * that directly, rather than trusting compareWorker()
                 * alone, is what actually determines whether this cache is
                 * usable.
                 */
                boolean cacheUsable = isSameWorker &&
                        criticalPath.getHead(worker) != null &&
                        criticalPath.getTail(worker) != null;

                System.err.println("[CRITPATH-DEBUG] cached graph isDoneBuilding=true, isSameWorker=" + isSameWorker //$NON-NLS-1$
                        + ", cacheUsable=" + cacheUsable); //$NON-NLS-1$

                if (cacheUsable) {
                    fCriticalPath = criticalPath;
                    return true;
                }
                // Else delete it -- covers both a genuinely different
                // worker and the isSameWorker=true-but-unusable case above.
                criticalPath.dispose();
                getHistoryTreeFilePath().toFile().delete();
                // Recreate a new graph with a brand new history tree file
                criticalPath = createGraph();
            } else if (windowed && criticalPath.isDoneBuilding()) {
                // Same reasoning as above: never trust a cached graph for a
                // windowed request, unconditionally recompute.
                criticalPath.dispose();
                getHistoryTreeFilePath().toFile().delete();
                criticalPath = createGraph();
            }
            if (criticalPath == null) {
                System.err.println("[CRITPATH-DEBUG] createGraph() after cache invalidation returned null"); //$NON-NLS-1$
                return false;
            }

            ITmfVertex end = null;
            if (windowEndObj instanceof Long) {
                // Only end.getTimestamp() is ever read by
                // ICriticalPathAlgorithm#computeCriticalPath -- this vertex
                // is never added to a graph or dereferenced for edges/
                // parentage, so it only needs to carry the right timestamp.
                end = graph.createVertex(worker, (Long) windowEndObj);
            }

            /*
             * Timed precisely around the one operation whose cost the
             * windowed vs. unbounded comparison in
             * critical_path_improvements.md is actually about, so this
             * number is comparable regardless of which caller (the manual
             * chat command, unbounded, or the normal question-answering
             * flow, windowed) reaches this method.
             */
            long computeStartNanos = System.nanoTime();
            criticalPath = cp.computeCriticalPath(criticalPath, head, end);
            long computeElapsedMs = (System.nanoTime() - computeStartNanos) / 1_000_000L;
            criticalPath.closeGraph(Long.MAX_VALUE);
            fCriticalPath = criticalPath;
            System.err.println("[CRITPATH-TIMING] computeCriticalPath took " + computeElapsedMs //$NON-NLS-1$
                    + " ms (windowed=" + windowed //$NON-NLS-1$
                    + (windowed ? " windowStart=" + windowStartObj + " windowEnd=" + windowEndObj : "") //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
                    + ")"); //$NON-NLS-1$
            System.err.println("[CRITPATH-DEBUG] computeCriticalPath succeeded, fCriticalPath set (windowed=" + windowed + ")"); //$NON-NLS-1$ //$NON-NLS-2$
            return true;
        } catch (CriticalPathAlgorithmException e) {
            System.err.println("[CRITPATH-DEBUG] computeCriticalPath THREW: " + e.getMessage()); //$NON-NLS-1$
            e.printStackTrace();
            Activator.getInstance().logError(NonNullUtils.nullToEmptyString(e.getMessage()), e);
        }
        return false;
    }

    /**
     * Walks a worker's own horizontal edge chain forward from its head,
     * returning the first vertex at or after {@code timestampNs}, or
     * {@code null} if the worker's recorded lifetime ends before reaching
     * that timestamp (or the worker has no head vertex at all).
     *
     * A more direct indexed lookup ({@link ITmfGraph#getVertexAt}) exists
     * and is documented to do exactly this, but its
     * {@code HistoryTreeTmfGraph} implementation was found to return null
     * for a timestamp genuinely inside a worker's real recorded range (see
     * the comment at this method's call site) -- so this walks the graph
     * manually instead, using only the same edge-traversal primitive
     * {@code computeCriticalPath()} itself already relies on.
     */
    private static @Nullable ITmfVertex findVertexAtOrAfter(
            ITmfGraph graph,
            IGraphWorker worker,
            long timestampNs) {

        ITmfVertex current = graph.getHead(worker);

        while (current != null && current.getTimestamp() < timestampNs) {
            ITmfEdge nextEdge = graph.getEdgeFrom(
                    current,
                    ITmfGraph.EdgeDirection.OUTGOING_HORIZONTAL_EDGE);

            if (nextEdge == null) {
                /*
                 * Reached the worker's tail without passing timestampNs --
                 * the requested window starts after this worker's last
                 * recorded activity.
                 */
                return null;
            }

            current = nextEdge.getVertexTo();
        }

        return current;
    }

    private static boolean compareWorker(IGraphWorker worker1, IGraphWorker worker2) {
        if (!worker1.getHostId().equals(worker2.getHostId())) {
            return false;
        }
        for (String key: worker1.getWorkerAspects().keySet()) {
            Object value1 = worker1.getWorkerAspects().get(key);
            Object value2 = worker2.getWorkerAspects().get(key);
            if (value1 == null && value2 == null) {
                continue;
            }
            if (value1 == null || value2 == null || !value1.equals(value2)) {
                return false;
            }
        }
        return true;
    }

    private @Nullable ITmfGraph createGraph() {
        Path htFile = getHistoryTreeFilePath();
        ITmfTrace trace = fGraphModule.getTrace();
        if (trace == null) {
            throw new NullPointerException("The graph should not be created if there is no trace set"); //$NON-NLS-1$
        }
        return createGraphInstance(htFile, fGraphModule.getWorkerSerializer(), trace.getStartTime().toNanos(), CRITICAL_PATH_GRAPH_VERSION);
    }

    private Path getHistoryTreeFilePath() {
        ITmfTrace trace = fGraphModule.getTrace();
        if (trace == null) {
            throw new NullPointerException("The graph should not be created if there is no trace set"); //$NON-NLS-1$
        }
        String fileDirectory = TmfTraceManager.getSupplementaryFileDir(trace);
        // FIXME Move somewhere where both graph and crit path module can use
        String id = fGraphModule.getId() + ".critPath"; //$NON-NLS-1$
        Path historyTreeFile = Paths.get(fileDirectory + id + ".ht"); //$NON-NLS-1$
        return historyTreeFile;
    }


    /**
     * Create the graph instance.
     *
     * The method needs to be implemented by children as the graph has to implement factories
     * and other methods that are specific to each use of the critical path module.
     *
     * @param htFile The history tree file used to store the graph
     * @param workerSerializer Responsible to read and write htfiles from disk
     * @param startTime Start time of the trace
     * @param version Version of the critical path graph used
     * @return The critical path graph
     *
     * @since 3.2
     */
    protected abstract @Nullable ITmfGraph createGraphInstance(Path htFile, WorkerSerializer workerSerializer, long startTime, int version);

    @Override
    protected void canceling() {
        // Do nothing
    }

    @Override
    protected void parameterChanged(String name) {
        closeCriticalPath();
        cancel();
        resetAnalysis();
        if (fScheduleOnParameterChange) {
            schedule();
        }
    }

    @Override
    public void dispose() {
        super.dispose();
        closeCriticalPath();
    }

    private void closeCriticalPath() {
        if (fCriticalPath != null) {
            fCriticalPath.dispose();
        }
        fCriticalPath = null;
    }

    private static ICriticalPathAlgorithm getAlgorithm(ITmfGraph graph) {
        return new OSCriticalPathAlgorithm(graph);
    }

    @Override
    public boolean canExecute(ITmfTrace trace) {
        /*
         * TODO: The critical path executes on a graph, so at least a graph must
         * be available for this trace
         */
        return true;
    }

    /**
     * Gets the graph for the critical path
     *
     * @return The critical path graph
     */
    @Override
    public @Nullable ITmfGraph getCriticalPathGraph() {
        return fCriticalPath;
    }

    @Override
    protected @NonNull String getFullHelpText() {
        return NonNullUtils.nullToEmptyString(Messages.CriticalPathModule_fullHelpText);
    }

    @Override
    protected @NonNull String getShortHelpText(ITmfTrace trace) {
        return getFullHelpText();
    }

    @Override
    protected @NonNull String getTraceCannotExecuteHelpText(@NonNull ITmfTrace trace) {
        return NonNullUtils.nullToEmptyString(Messages.CriticalPathModule_cantExecute);
    }

}
