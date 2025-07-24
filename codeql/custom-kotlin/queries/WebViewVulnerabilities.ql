/**
 * @name Hardcoded credentials in Kotlin
 * @description Finds hardcoded secrets like passwords, API keys, or tokens in Kotlin code.
 * @kind problem
 * @problem.severity error
 * @tags security
 *       external/cwe/cwe-798
 *       external/cwe/cwe-259
 */

import kotlin
import semmle.code.kotlin.Expressions
import semmle.code.kotlin.Statements
import semmle.code.kotlin.Declarations

predicate isSensitiveName(string name) {
  name.toLowerCase().matches("%password%") or
  name.toLowerCase().matches("%secret%") or
  name.toLowerCase().matches("%token%") or
  name.toLowerCase().matches("%apikey%") or
  name.toLowerCase().matches("%auth%")
}

predicate isHardcodedCredential(Expr e) {
  e instanceof StringLiteral and
  e.(StringLiteral).getValue().length() > 5 and
  not e.toString().matches("%BuildConfig.%") // Exclude build-time configs
}

from VariableDeclarator v, Expr init
where
  isSensitiveName(v.getName()) and
  v.hasInitializer(init) and
  isHardcodedCredential(init)
select v, "Possible hardcoded credential: " + v.getName()
