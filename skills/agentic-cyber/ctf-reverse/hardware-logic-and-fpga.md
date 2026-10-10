# Hardware logic and FPGA CTF workflow

Use this note for supplied Verilog/VHDL/SystemVerilog, synthesized netlists, simulation harnesses, FPGA bitstream-adjacent artifacts, or logic-analyzer captures. Start from the supplied model/harness; do not interact with physical hardware outside an explicitly authorized lab.

## Establish the execution model

1. Identify the top module, clock/reset polarity, input/output widths, simulator/harness, and success condition.
2. Separate combinational logic from sequential state. Record each register’s reset value, clock edge, enable, and next-state equation.
3. Verify HDL width, sign extension, truncation, blocking/nonblocking assignment order, and latch inference before interpreting it as ordinary software.
4. Translate the harness into a timeline: reset cycles -> input cycles -> expected output/flag check.

## High-value CTF patterns

- **Reset/initial-state mismatch:** the harness assumes a reset sequence the design does not enforce, or a register remains X/uninitialized in simulation.
- **Width and signedness bug:** a truncated comparison, wraparound counter, or signed/unsigned cast alters a gate or password check.
- **Clock-edge/state sequencing:** a valid state is reachable only by a particular input order, enable cycle, or simultaneous signal transition.
- **Combinational-cycle/latch behavior:** incomplete assignments retain a prior value or make a condition history-dependent.
- **Synthesis versus simulation difference:** challenge behavior depends on the supplied simulator, an unconnected signal, or a generated netlist rather than RTL intent.

## Solve method

1. Create a minimal testbench that prints inputs, state registers, and outputs at every clock edge.
2. Reduce the gate/state transition system into a truth table, SAT/SMT model, or brute-force search only after confirming reset and bit widths.
3. Re-run the candidate sequence through the original harness and keep the waveform or cycle log as evidence.
4. If only a bitstream or firmware wrapper is supplied, pivot to `platforms-hardware.md` and reverse the surrounding loader/interface before guessing FPGA internals.

## Source technique examples

- [Google CTF 2020 “basics” Verilog write-up](https://ctftime.org/writeup/23026)
- [“What’s going on the FPGA?” CTF write-up](https://gyokhan.com/ctf-challenge-whats-going-on-fpga/)
