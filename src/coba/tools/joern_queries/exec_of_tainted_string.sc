// Joern Scala script: detect calls that pass externally-tainted data to
// exec-like sinks (system, exec, Runtime.exec, subprocess.run, eval, ...).
// Output: JSON array on stdout.

@main def main(cpg: String): Unit = {
  importCpg(cpg)

  val sources = cpg.call.name(
    ".*request.*|.*input.*|.*argv.*|.*getenv.*|.*getParameter.*|" +
    ".*Scanner.*|.*ReadLine.*"
  ).l

  val sinks = cpg.call.name(
    "exec|system|popen|.*subprocess\\.run.*|.*subprocess\\.call.*|" +
    "Runtime\\.getRuntime\\.exec|eval|.*ProcessBuilder.*"
  ).l

  val flows = sinks.reachableByFlows(sources).p

  val out = flows.map { f =>
    val elems = f.elements
    val last  = elems.lastOption.map(_.location)
    val line  = last.map(_.lineNumber.getOrElse(0)).getOrElse(0)
    val msg   = "Tainted data reaches an exec-like sink"
    s"""{"line":${line},"message":"${msg}"}"""
  }
  println("[" + out.mkString(",") + "]")
}
