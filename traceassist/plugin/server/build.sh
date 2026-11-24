#!/bin/bash
# Builds the TraceAssist server bundle and, with --install, installs it in the Trace Server.
#
# The bundle is the plug-in's UI-free sources (every file in src/.../views except the two
# views) plus server/src, compiled against the Trace Server's own jars only: anything that
# needs SWT or the workbench fails to compile here. The skills and view cards are packaged
# too, but the installed bundle reads them from this project (traceassist.home), so an
# edited skill applies to Eclipse and the server alike.
#
# The Eclipse side runs the workspace's Trace Compass, whose analysis.graph.core has one
# change: AbstractCriticalPathModule's windowStartNs/windowEndNs parameters (critical path
# over a window). --install patches that class into the server's analysis.graph.core jar
# (original kept in <server>/backup-before-traceassist/) so both compute alike.
#
# Usage: server/build.sh [--install]      (TRACE_SERVER=<server dir> to use another server)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PROJECT=$(dirname "$HERE")
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
SERVER=${TRACE_SERVER:-"$REPO/trace-server/trace-compass-server"}
PLUGINS="$SERVER/plugins"
BACKUP="$SERVER/backup-before-traceassist"
# Where org.eclipse.jdt.annotation_2*.jar is (an Eclipse PDE bundle pool, or any folder holding it).
POOL=${ECLIPSE_BUNDLE_POOL:-"$HOME/eclipse-workspace/.metadata/.plugins/org.eclipse.pde.core/.bundle_pool/plugins"}
GRAPH_SRC="$REPO/traceassist/tracecompass-patch/src"
GRAPH_CLASS=org/eclipse/tracecompass/analysis/graph/core/criticalpath/AbstractCriticalPathModule
JAVAC=${JAVAC:-/usr/lib/jvm/java-21-openjdk/bin/javac}
NAME=org.eclipse.tracecompass.traceassist.server
VERSION=$(sed -n 's/^Bundle-Version: //p' "$HERE/META-INF/MANIFEST.MF" | tr -d '\r')
JAR="$HERE/build/${NAME}_${VERSION}.jar"

jar_of() { # the jar of a bundle in the server's plugins (the backed-up original if there is one)
    local found
    found=$(ls "$PLUGINS" | grep -E "^$1_[0-9]" | grep '\.jar$' | sort | tail -1)
    [ -n "$found" ] || { echo "bundle $1 not in $PLUGINS" >&2; exit 1; }
    if [ -f "$BACKUP/$found" ]; then echo "$BACKUP/$found"; else echo "$PLUGINS/$found"; fi
}

javac_or_fail() { # javac_or_fail <log> <args...>
    local log=$1; shift
    if ! "$JAVAC" -nowarn -proc:none -encoding UTF-8 --release 21 "$@" > "$log" 2>&1; then
        grep -v '^Note:' "$log" >&2
        echo "compile failed" >&2
        exit 1
    fi
}

# The bundles the manifest requires (and what they re-export), nothing else.
CP=""
for b in org.eclipse.core.runtime org.eclipse.core.resources org.eclipse.core.jobs org.eclipse.equinox.common org.eclipse.osgi com.google.gson com.google.guava \
         org.eclipse.tracecompass.common.core org.eclipse.tracecompass.statesystem.core \
         org.eclipse.tracecompass.tmf.core org.eclipse.tracecompass.tmf.ctf.core \
         org.eclipse.tracecompass.analysis.os.linux.core org.eclipse.tracecompass.analysis.graph.core \
         org.eclipse.tracecompass.lttng2.kernel.core org.eclipse.tracecompass.lttng2.common.core; do
    CP="$CP:$(jar_of $b)"
done
# @Nullable only: CLASS retention, not needed at run time.
CP="$CP:$(ls $POOL/org.eclipse.jdt.annotation_2*.jar | grep -v source | tail -1)"
CP=${CP#:}

rm -rf "$HERE/build"
mkdir -p "$HERE/build/classes" "$HERE/build/graph-patch/classes"

# 1. The workspace's AbstractCriticalPathModule, compiled against the server's jars.
javac_or_fail "$HERE/build/graph-patch/javac.log" -cp "$CP" -d "$HERE/build/graph-patch/classes" "$GRAPH_SRC/$GRAPH_CLASS.java"

# 2. The bundle, against the server's jars with that class first.
VIEWS="$PROJECT/src/org/eclipse/tracecompass/helloworld/ui/views"
SOURCES=$(find "$VIEWS" "$HERE/src" -name '*.java' ! -name HelloWorldView.java ! -name HelloWorldRagView.java | sort)
echo "Compiling $(echo "$SOURCES" | wc -l) files against the Trace Server's bundles"
{ echo "-cp"; echo "\"$HERE/build/graph-patch/classes:$CP\""; echo "$SOURCES" | sed 's/.*/"&"/'; } > "$HERE/build/javac.args"
javac_or_fail "$HERE/build/javac.log" -d "$HERE/build/classes" "@$HERE/build/javac.args"
cp -r "$PROJECT/skills" "$HERE/build/classes/skills"
jar --create --file "$JAR" --manifest "$HERE/META-INF/MANIFEST.MF" -C "$HERE/build/classes" .
echo "Built $JAR ($(du -h "$JAR" | cut -f1))"

# 3. The executable jar (java -jar traceassist-server.jar start --server <dir>): a launcher that
#    installs the bundle and the critical-path patch in any Trace Server and starts it with the
#    user's own OpenAI API key. It carries the bundle and the patched classes; Java 11+ runs it.
LAUNCHER="$HERE/build/launcher/classes"
mkdir -p "$LAUNCHER/bundle" "$LAUNCHER/patch"
javac_or_fail "$HERE/build/launcher/javac.log" --release 11 -d "$LAUNCHER" \
    $(find "$HERE/launcher/src" -name '*.java')
cp "$JAR" "$LAUNCHER/bundle/"
(cd "$HERE/build/graph-patch/classes" && find . -name '*.class' | sed 's|^\./||' | sort) > "$HERE/build/launcher/patch.list"
(cd "$HERE/build/graph-patch/classes" && cp --parents $(cat "$HERE/build/launcher/patch.list") "$LAUNCHER/patch/")
GRAPH_BUILT=$(basename "$(jar_of org.eclipse.tracecompass.analysis.graph.core)" .jar)
{
    echo "bundle.file=${NAME}_${VERSION}.jar"
    echo "graph.version=${GRAPH_BUILT#org.eclipse.tracecompass.analysis.graph.core_}"
    echo "patch.classes=$(paste -sd, "$HERE/build/launcher/patch.list")"
} > "$LAUNCHER/traceassist.properties"
EXECUTABLE="$HERE/build/traceassist-server.jar"
jar --create --file "$EXECUTABLE" --main-class org.eclipse.tracecompass.traceassist.launcher.Main -C "$LAUNCHER" .
echo "Built $EXECUTABLE ($(du -h "$EXECUTABLE" | cut -f1)): java -jar $(basename "$EXECUTABLE") start --server <trace-server folder>"

[ "${1:-}" = "--install" ] || exit 0

# 3. Patch the server's analysis.graph.core (from the original, kept in the backup).
mkdir -p "$BACKUP"
GRAPH_JAR=$(ls "$PLUGINS" | grep -E '^org\.eclipse\.tracecompass\.analysis\.graph\.core_[0-9].*\.jar$' | sort | tail -1)
[ -f "$BACKUP/$GRAPH_JAR" ] || cp "$PLUGINS/$GRAPH_JAR" "$BACKUP/"
(
    cd "$HERE/build/graph-patch"
    cp "$BACKUP/$GRAPH_JAR" patched.jar
    zip -q -d patched.jar 'META-INF/ECLIPSE_.SF' 'META-INF/ECLIPSE_.RSA' || true  # no longer signed
    jar --update --file patched.jar -C classes .
)
cp "$HERE/build/graph-patch/patched.jar" "$PLUGINS/$GRAPH_JAR"
echo "Patched $GRAPH_JAR with the workspace's AbstractCriticalPathModule (original in $BACKUP)"

# 4. The bundle, started with the server; settings in config.ini.
CONFIG="$SERVER/configuration/config.ini"
[ -f "$BACKUP/config.ini" ] || cp "$CONFIG" "$BACKUP/config.ini"
rm -f "$PLUGINS/${NAME}"_*.jar
cp "$JAR" "$PLUGINS/"
python3 - "$CONFIG" "${NAME}_${VERSION}.jar" "$PROJECT" <<'EOF'
import re, sys
config, jar, home = sys.argv[1:]
text = open(config).read()
entry = r"reference\:file\:" + jar + r"@4\:start"
# drop any older version of the bundle, then add this one
text = re.sub(r",reference\\:file\\:org\.eclipse\.tracecompass\.traceassist\.server_[^,\n]*", "", text)
text = re.sub(r"^(osgi\.bundles=.*)$", lambda m: m.group(1) + "," + entry, text, count=1, flags=re.M)
for key, value in (("traceassist.home", home), ("traceassist.port", "8092")):
    if not re.search(rf"^{re.escape(key)}=", text, re.M):
        text = text.rstrip("\n") + f"\n{key}={value}\n"
open(config, "w").write(text)
EOF
echo "Installed in $PLUGINS and $CONFIG (originals in $BACKUP). Restart the Trace Server with -clean."
