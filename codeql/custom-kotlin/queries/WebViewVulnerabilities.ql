/**
 * @name WebView vulnerabilities in Kotlin
 * @description Identifies potential security vulnerabilities in Android WebView usage
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id kotlin/webview-vulnerabilities
 * @tags security
 *       external/cwe/cwe-079
 *       external/cwe/cwe-200
 *       external/cwe/cwe-094
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking

// WebView class and related classes
class WebViewClass extends RefType {
  WebViewClass() {
    this.hasQualifiedName("android.webkit", "WebView") or
    this.hasQualifiedName("android.webkit", "WebSettings") or
    this.hasQualifiedName("android.webkit", "WebViewClient") or
    this.hasQualifiedName("android.webkit", "WebChromeClient")
  }
}

// Dangerous WebView methods
class DangerousWebViewMethod extends Method {
  DangerousWebViewMethod() {
    this.getDeclaringType() instanceof WebViewClass and
    (
      this.hasName("loadUrl") or
      this.hasName("loadData") or
      this.hasName("loadDataWithBaseURL") or
      this.hasName("evaluateJavascript") or
      this.hasName("addJavascriptInterface")
    )
  }
}

// WebSettings dangerous configurations
class DangerousWebSettingsMethod extends Method {
  DangerousWebSettingsMethod() {
    this.getDeclaringType().hasQualifiedName("android.webkit", "WebSettings") and
    (
      this.hasName("setJavaScriptEnabled") or
      this.hasName("setAllowFileAccess") or
      this.hasName("setAllowFileAccessFromFileURLs") or
      this.hasName("setAllowUniversalAccessFromFileURLs") or
      this.hasName("setAllowContentAccess") or
      this.hasName("setMixedContentMode") or
      this.hasName("setDomStorageEnabled")
    )
  }
}

// Taint tracking for user input to WebView
class WebViewTaintTrackingConfig extends TaintTracking::Configuration {
  WebViewTaintTrackingConfig() { this = "WebViewTaintTracking" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m |
      source.asExpr().(MethodAccess).getMethod() = m and
      (
        // Intent data sources
        m.hasName("getStringExtra") or
        m.hasName("getDataString") or
        m.hasName("getData") or
        // Bundle sources
        m.hasName("getString") or
        // Network/HTTP sources
        m.getDeclaringType().hasQualifiedName("java.net", "URL") or
        m.getDeclaringType().hasQualifiedName("okhttp3", "Response") or
        // User input sources
        m.getDeclaringType().hasQualifiedName("android.widget", "EditText") and
        m.hasName("getText")
      )
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      sink.asExpr() = ma.getAnArgument() and
      ma.getMethod() instanceof DangerousWebViewMethod
    )
  }
}

// Query for JavaScript enabled without proper validation
from MethodAccess jsEnabledCall, Literal trueLiteral
where
  jsEnabledCall.getMethod().hasName("setJavaScriptEnabled") and
  jsEnabledCall.getArgument(0) = trueLiteral and
  trueLiteral.getValue() = "true"
select jsEnabledCall, "JavaScript is enabled in WebView without proper security considerations"

or

// Query for file access vulnerabilities
from MethodAccess fileAccessCall, Literal trueLiteral
where
  fileAccessCall.getMethod() instanceof DangerousWebSettingsMethod and
  (
    fileAccessCall.getMethod().hasName("setAllowFileAccess") or
    fileAccessCall.getMethod().hasName("setAllowFileAccessFromFileURLs") or
    fileAccessCall.getMethod().hasName("setAllowUniversalAccessFromFileURLs")
  ) and
  fileAccessCall.getArgument(0) = trueLiteral and
  trueLiteral.getValue() = "true"
select fileAccessCall, "Dangerous file access permissions enabled in WebView: " + fileAccessCall.getMethod().getName()

or

// Query for JavaScript interface injection vulnerabilities
from MethodAccess jsInterfaceCall
where
  jsInterfaceCall.getMethod().hasName("addJavascriptInterface")
select jsInterfaceCall, "JavaScript interface added to WebView - ensure proper @JavascriptInterface annotations and input validation"

or

// Query for mixed content vulnerabilities
from MethodAccess mixedContentCall, Literal allowValue
where
  mixedContentCall.getMethod().hasName("setMixedContentMode") and
  mixedContentCall.getArgument(0) = allowValue and
  (
    allowValue.getValue() = "0" or // MIXED_CONTENT_ALWAYS_ALLOW
    allowValue.getValue().toString().matches("%ALWAYS_ALLOW%")
  )
select mixedContentCall, "Mixed content always allowed in WebView - potential security risk"

or

// Query for taint tracking from user input to WebView
from WebViewTaintTrackingConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "User input flows to WebView without proper sanitization"

or

// Query for hardcoded URLs in WebView calls
from MethodAccess webviewCall, StringLiteral url
where
  webviewCall.getMethod() instanceof DangerousWebViewMethod and
  webviewCall.getAnArgument() = url and
  url.getValue().regexpMatch("https?://.*")
select webviewCall, "Hardcoded URL loaded in WebView: " + url.getValue()

or

// Query for missing WebViewClient implementation
from MethodAccess loadUrlCall, WebView webview
where
  loadUrlCall.getMethod().hasName("loadUrl") and
  loadUrlCall.getQualifier() = webview.getAnAccess() and
  not exists(MethodAccess setClientCall |
    setClientCall.getMethod().hasName("setWebViewClient") and
    setClientCall.getQualifier() = webview.getAnAccess()
  )
select loadUrlCall, "WebView loads URL without custom WebViewClient - may allow navigation to external sites"

or

// Query for DOM storage enabled without consideration
from MethodAccess domStorageCall, Literal trueLiteral
where
  domStorageCall.getMethod().hasName("setDomStorageEnabled") and
  domStorageCall.getArgument(0) = trueLiteral and
  trueLiteral.getValue() = "true"
select domStorageCall, "DOM storage enabled in WebView - ensure data sensitivity is considered"
