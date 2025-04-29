import chalk from 'chalk';

/**
 * Exports an IDA Pro Python script for analyzing a Solana program binary.
 * The script configures IDA Pro for sBPF architecture, annotates syscalls,
 * marks control flow structures, and highlights potential risks.
 *
 * @param {Object} analysis - Binary analysis insights from analyzer.js, containing:
 *   - insights: Object with instructions, syscalls, suspectedType, reentrancyRisk,
 *              controlFlow, usesBorsh, hiddenMint, authorityHolders, address
 * @returns {Promise<string>} - IDA Pro Python script as a string.
 * @throws {Error} - If analysis insights are invalid.
 */
export async function exportIdaScript(analysis) {
  try {
    // Validate input
    if (!analysis?.insights || typeof analysis.insights !== 'object') {
      throw new Error('Invalid or missing analysis insights');
    }

    const { insights } = analysis;
    const requiredFields = ['instructions', 'syscalls', 'suspectedType', 'reentrancyRisk', 'controlFlow', 'address'];
    for (const field of requiredFields) {
      if (!(field in insights)) {
        throw new Error(`Missing required field: ${field}`);
      }
    }

    // Initialize script with header and setup
    const scriptLines = [
      '# SolProof IDA Pro Script for Solana sBPF Analysis',
      `# Generated for program: ${insights.address}`,
      `# Timestamp: ${new Date().toISOString()}`,
      'from idaapi import *',
      'import idc',
      '',
      '# Configure IDA Pro for Solana BPF (sBPF) architecture',
      'def setup_sBPF():',
      '    set_processor_type("sBPF", SETPROC_ALL)',
      '    print("Configured IDA Pro for sBPF architecture")',
      'setup_sBPF()',
      '',
      '# Binary Metadata',
      `binary_size = ${insights.instructions * 8} # Estimated bytes`,
      `instruction_count = ${insights.instructions}`,
      `program_type = "${insights.suspectedType}"`,
      `syscalls = ${JSON.stringify(insights.syscalls)}`,
      `reentrancy_risk = "${insights.reentrancyRisk}"`,
      `branches = ${insights.controlFlow.branches}`,
      `loops = ${insights.controlFlow.loops}`,
      'print(f"Binary Size: {binary_size} bytes")',
      'print(f"Instruction Count: {instruction_count}")',
      'print(f"Suspected Program Type: {program_type}")',
      'print(f"Reentrancy Risk: {reentrancy_risk}")',
      'print(f"Control Flow: {branches} branches, {loops} loops")',
      '',
      '# Define entry point',
      'add_entry(0x0, 0x0, "program_entry", True)',
      'print("Defined program entry point at 0x0")',
      '',
      '# Annotate syscalls',
      'def annotate_syscalls():',
      '    for syscall in syscalls:',
      '        print(f"Annotating syscall: {syscall}")',
      '        # Placeholder addresses for syscalls (real analysis would map to binary offsets)',
      '        syscall_addr = 0x100 if syscall == "sol_invoke" else \\',
      '                      0x200 if syscall == "sol_verify_signature" else \\',
      '                      0x300 if syscall == "sol_alloc_free" else 0x400',
      '        idc.set_cmt(syscall_addr, f"Syscall: {syscall}", True)',
      'annotate_syscalls()',
      '',
      '# Annotate control flow',
      'def annotate_control_flow():',
      `    branch_count = ${insights.controlFlow.branches}`,
      `    loop_count = ${insights.controlFlow.loops}`,
      '    # Simplified: Assume branches and loops at regular intervals',
      '    for i in range(branch_count):',
      '        addr = 0x1000 + i * 0x100',
      '        idc.set_cmt(addr, "Control Flow: Branch", True)',
      '    for i in range(loop_count):',
      '        addr = 0x2000 + i * 0x100',
      '        idc.set_cmt(addr, "Control Flow: Loop", True)',
      '    print(f"Annotated {branch_count} branches and {loop_count} loops")',
      'annotate_control_flow()',
      '',
      '# Add instruction-level comments (simplified)',
      'def annotate_instructions():',
      `    for i in range(min(${insights.instructions}, 100)): # Limit to 100 for performance`,
      '        addr = i * 8',
      '        idc.set_cmt(addr, f"Instruction {i}", True)',
      '    print("Annotated instructions")',
      'annotate_instructions()',
      '',
      '# Highlight potential risks',
      'def highlight_risks():',
    ];

    // Add risk-specific comments
    if (insights.hiddenMint) {
      scriptLines.push(
        '    idc.set_cmt(0x500, "Risk: Potential hidden mint detected", True)',
        '    print("Warning: Hidden mint detected")'
      );
    }
    if (insights.reentrancyRisk === 'Moderate' || insights.reentrancyRisk === 'High') {
      scriptLines.push(
        `    idc.set_cmt(0x600, "Risk: ${insights.reentrancyRisk} reentrancy risk", True)`,
        `    print("Warning: ${insights.reentrancyRisk} reentrancy risk detected")`
      );
    }
    if (insights.usesBorsh) {
      scriptLines.push(
        '    idc.set_cmt(0x700, "Note: Borsh serialization detected", True)',
        '    print("Note: Borsh serialization detected")'
      );
    }
    if (insights.authorityHolders.length === 1) {
      scriptLines.push(
        '    idc.set_cmt(0x800, "Risk: Single authority detected", True)',
        '    print("Warning: Single authority detected")'
      );
    }

    scriptLines.push(
      'highlight_risks()',
      '',
      '# Finalize analysis',
      'print("SolProof IDA Pro analysis complete for program: ' + program_type + '")'
    );

    return scriptLines.join('\n');
  } catch (err) {
    console.warn(chalk.yellow(`IDA script export failed: ${err.message}`));
    return [
      '# SolProof IDA Pro Script',
      `# Error: Failed to generate script for program analysis`,
      `print("Error: ${err.message}")`,
    ].join('\n');
  }
}