// Joern Scala script: extract a coarse call graph for an entire CPG.
//
// Output: JSON array on stdout. Each element has the shape
//   {
//     "file": "/abs/path/to/source",
//     "function": "function_name",
//     "line": 42,
//     "callees": ["other_fn", "module.api"],
//     "callers": ["caller_one", "caller_two"]
//   }
//
// Joern (Scala 3) script entry point — invoked via:
//   joern --script call_graph.sc --param cpg=/path/to.cpg.bin

@main def main(cpg: String): Unit = {
  importCpg(cpg)

  val records = cpg.method.l.map { m =>
    val callees = m.callee.name.l.distinct.take(50)
    val callers = m.caller.name.l.distinct.take(50)
    val file    = m.filename
    val name    = m.name
    val line    = m.lineNumber.getOrElse(0)

    val esc = (s: String) => s.replace("\\", "\\\\").replace("\"", "\\\"")

    val calleesJ = callees.map(c => "\"" + esc(c) + "\"").mkString(",")
    val callersJ = callers.map(c => "\"" + esc(c) + "\"").mkString(",")

    s"""{"file":"${esc(file)}","function":"${esc(name)}","line":${line},""" +
    s""""callees":[${calleesJ}],"callers":[${callersJ}]}"""
  }
  println("[" + records.mkString(",") + "]")
}
