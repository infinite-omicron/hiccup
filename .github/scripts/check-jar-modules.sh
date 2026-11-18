#!/usr/bin/env bash
# Fails if hiccup-burp.jar needs a JDK module that Burp's bundled JRE lacks.
# Burp ships a trimmed runtime (no jdk.httpserver, for example), so code that
# works on a full JDK can fail to load in Burp (issue #7).
# Usage: check-jar-modules.sh <hiccup-burp.jar>
set -euo pipefail

jar="${1:?usage: check-jar-modules.sh <hiccup-burp.jar>}"

# Modules of Burp Suite 2026.11's bundled JRE (Java 26), from its "release" file.
burp_modules="java.base java.compiler java.datatransfer java.xml java.prefs java.desktop java.instrument java.logging java.management java.security.sasl java.naming java.rmi java.management.rmi java.net.http java.scripting java.security.jgss java.transaction.xa java.sql java.sql.rowset java.xml.crypto java.se jdk.accessibility jdk.internal.jvmstat jdk.attach jdk.charsets jdk.internal.opt jdk.zipfs jdk.compiler jdk.crypto.cryptoki jdk.crypto.ec jdk.jdwp.agent jdk.jdi jdk.management jdk.net jdk.security.auth jdk.security.jgss jdk.unsupported"

# The Montoya API is provided by Burp at runtime; find it in the Gradle cache.
montoya=$(find "${GRADLE_USER_HOME:-$HOME/.gradle}/caches" -name 'montoya-api-*.jar' -print -quit)
[[ -n "$montoya" ]] || { echo "montoya-api jar not found in the Gradle cache; build the jar first" >&2; exit 1; }

needed=$(jdeps --multi-release 17 --ignore-missing-deps -summary --class-path "$montoya" "$jar" \
  | awk -F' -> ' '$2 !~ /\.jar$/ {print $2}' | sort -u)

bad=0
for m in $needed; do
  if [[ " $burp_modules " != *" $m "* ]]; then
    echo "::error::hiccup-burp.jar needs module $m, which Burp's bundled JRE does not include"
    bad=1
  fi
done
[[ $bad -eq 0 ]] || exit 1
echo "hiccup-burp.jar only needs modules Burp ships: ${needed//$'\n'/ }"
