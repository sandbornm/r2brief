// Targeted post-script: decompile one or more functions by hex address.
// Args: <output-path> <hex-addr> [hex-addr...]
// Each addr may be a call site; the containing function is decompiled.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;

import java.util.ArrayList;
import java.util.LinkedHashSet;

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
            long offset;
            try {
                offset = Long.parseLong(hex, 16);
            } catch (NumberFormatException e) {
                out.println("// no function at " + args[i]);
                continue;
            }
            Function f = findOrCreateFunction(offset);
            if (f == null) {
                out.println("// no function at " + args[i]);
                continue;
            }
            String entry = "0x" + Long.toHexString(f.getEntryPoint().getOffset());
            out.println("// ==== " + f.getName() + " @ " + entry + " ====");
            if (!entry.equalsIgnoreCase("0x" + hex)
                    && !entry.equalsIgnoreCase("0x" + Long.toHexString(offset))) {
                out.println("// requested " + args[i]);
            }
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

    private Function findOrCreateFunction(long offset) {
        for (Address a : candidateAddresses(offset)) {
            Function f = getFunctionAt(a);
            if (f == null) {
                f = getFunctionContaining(a);
            }
            if (f != null) {
                return f;
            }
        }
        Memory memory = currentProgram.getMemory();
        for (Address a : candidateAddresses(offset)) {
            if (memory.contains(a)) {
                Function created = createFunction(a, null);
                if (created != null) {
                    return created;
                }
            }
        }
        return null;
    }

    private Address[] candidateAddresses(long offset) {
        AddressSpace space = currentProgram.getAddressFactory().getDefaultAddressSpace();
        long image = currentProgram.getImageBase().getOffset();
        LinkedHashSet<Long> offsets = new LinkedHashSet<Long>();
        offsets.add(Long.valueOf(offset));
        if (image != 0) {
            offsets.add(Long.valueOf(image + offset));
            if (offset >= image) {
                offsets.add(Long.valueOf(offset - image));
            }
        }
        ArrayList<Address> addrs = new ArrayList<Address>();
        for (Long candidate : offsets) {
            try {
                addrs.add(space.getAddress(candidate.longValue()));
            } catch (AddressOutOfBoundsException e) {
                // skip unmapped / overflowed candidate
            }
        }
        return addrs.toArray(new Address[0]);
    }
}
