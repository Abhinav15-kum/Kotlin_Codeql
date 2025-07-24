/**
 * @name Insecure WebView JavaScript Enabled
 * @description Detects cases where WebView enables JavaScript in Android apps written in Kotlin.
 * @kind problem
 * @problem.severity warning
 * @id kotlin/android/insecure-webview-jsenabled
 * @tags security
 */

import kotlin
import semmle.code.kotlin.controlflow.DataFlow

from
  MethodAccess ma,
  PropertyAccess pa,
  DataFlow::Node source,
  DataFlow::Node sink
where
  pa.getName() = "javaScriptEnabled" and
  ma.getMethod().getName() = "setJavaScriptEnabled" and
  pa.getQualifier().getType().getName().matches("WebView") and
  sink.asExpr() = ma.getArgument(0) and
  source.asExpr() instanceof BooleanLiteral and
  source.asExpr().toString() = "true"
select
  ma,
  "Insecure WebView configuration: JavaScript is enabled without validation."
