/**
 * @name WebView vulnerability detector
 * @description Detects potentially dangerous WebView usage in Kotlin Android code.
 * @kind path-problem
 * @problem.severity error
 * @id kotlin/android/webview-vulnerability
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-094
 *       external/cwe/cwe-1022
 */

import kotlin
import semmle.code.kotlin.dataflow.DataFlow
import semmle.code.android.AndroidWebView

/**
 * Configuration for tracking tainted data into WebView sinks
 */
class WebViewTaintConfig extends TaintTracking::Configuration {
  WebViewTaintConfig() { this = "WebViewTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof Parameter or
    exists(Method m |
      m.hasName("getIntent") or
      m.hasName("getExtras") or
      m.hasName("getStringExtra")
    |
      source.asExpr() = m.getAnAccess()
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess call |
      call.getMethod().getDeclaringType().hasQualifiedName("android.webkit", "WebView") and
      (
        call.getMethod().getName() = "loadUrl" or
        call.getMethod().getName() = "loadDataWithBaseURL" or
        call.getMethod().getName() = "addJavascriptInterface"
      ) |
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // Add sanitizer logic if known
    false
  }
}

/**
 * Check whether JavaScript is explicitly enabled
 */
predicate javascriptEnabled(android.WebSettings settings) {
  exists(MethodAccess ma |
    ma.getMethod().hasName("setJavaScriptEnabled") and
    ma.getQualifier().getType() instanceof android.WebSettings and
    ma.getArgument(0).toString() = "true" and
    ma.getQualifier() = settings
  )
}

/**
 * Run the taint analysis and report issues
 */
from WebViewTaintConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Untrusted input flows into WebView method: " + sink.getNode().toString() + ". This can lead to RCE or XSS if not properly validated."
