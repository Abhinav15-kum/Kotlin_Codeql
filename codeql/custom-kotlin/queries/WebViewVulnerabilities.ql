/**
 * @name Insecure WebView JavaScript Enabled
 * @description Detects cases where WebView enables JavaScript in Android apps written in Kotlin.
 * @kind problem
 * @problem.severity warning
 * @id kotlin/android/insecure-webview-jsenabled
 * @tags security
 */

import kotlin

from MethodAccess ma
where
  ma.getMethod().getName() = "setJavaScriptEnabled" and
  ma.getReceiverType().hasQualifiedName("android.webkit", "WebView") and
  exists(BooleanLiteral b | ma.getArgument(0) = b and b.getBooleanValue() = true)
select
  ma,
  "Insecure WebView configuration: JavaScript is enabled without validation."
