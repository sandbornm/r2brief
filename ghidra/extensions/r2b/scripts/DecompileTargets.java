// Targeted post-script: decompile one or more functions by hex address.
// Args: <output-path> <hex-addr> [hex-addr...]
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileTargets extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("[r2b] DecompileTargets: need <output> <hex-addr>...");
            return;
        }
        java.io.PrintWriter out = new java.io.PrintWriter(new java.io.FileWriter(args[0]));
        DecompInterface ifc = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        opts.grabFromProgram(currentProgram);
        ifc.setOptions(opts);
        if (!ifc.openProgram(currentProgram)) {
            out.println("// openProgram failed: " + ifc.getLastMessage());
            out.close();
            return;
        }
        for (int i = 1; i < args.length; i++) {
            String hex = args[i].startsWith("0x") || args[i].startsWith("0X")
                ? args[i].substring(2) : args[i];
            Address a = toAddr(Long.parseLong(hex, 16));
            Function f = getFunctionAt(a);
            if (f == null) {
                f = getFunctionContaining(a);
            }
            if (f == null) {
                out.println("// no function at " + args[i]);
                continue;
            }
            out.println("// ==== " + f.getName() + " @ " + args[i] + " ====");
            try {
                DecompileResults res = ifc.decompileFunction(f, 120, monitor);
                if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                    out.println(res.getDecompiledFunction().getC());
                } else {
                    out.println("// decompile failed: '" + res.getErrorMessage() + "'");
                }
            } catch (Exception e) {
                out.println("// exception: " + e);
            }
            out.println();
        }
        ifc.dispose();
        out.close();
    }
}
