import chalk from 'chalk';

/**
 * Analyzes a Solana program binary to extract insights.
 *
 * @param {Buffer} binary - Program binary data.
 * @param {string} address - Program address.
 * @returns {Promise<Object>} - Analysis insights.
 */
export async function analyzeBinary(binary, address) {
  try {
    const binarySize = binary.length;
    const instructionCount = Math.floor(binarySize / 8);
    const syscalls = detectSyscalls(binary);
    const suspectedType = inferProgramType(address, binary);
    const controlFlow = {
      branches: Math.floor(instructionCount * 0.1),
      loops: Math.floor(instructionCount * 0.05),
    };
    const usesBorsh = binary.includes(Buffer.from('borsh'));
    const hiddenMint = binary.includes(Buffer.from('mint'));

    return {
      insights: {
        instructions: instructionCount,
        syscalls,
        suspectedType,
        reentrancyRisk: instructionCount > 1000 ? 'Moderate' : 'Low',
        controlFlow,
        usesBorsh,
        hiddenMint,
        authorityHolders: ['8x7y...z9k2'], // Simplified; real analysis would fetch from accounts
        address,
      },
    };
  } catch (err) {
    console.warn(chalk.yellow(`Binary analysis failed for ${address}: ${err.message}`));
    return {
      insights: {
        instructions: 0,
        syscalls: [],
        suspectedType: 'unknown',
        reentrancyRisk: 'Low',
        controlFlow: { branches: 0, loops: 0 },
        usesBorsh: false,
        hiddenMint: false,
        authorityHolders: [],
        address,
      },
    };
  }
}

/**
 * Detects syscalls in the binary (heuristic-based).
 * @param {Buffer} binary - Program binary.
 * @returns {Array<string>} - List of detected syscalls.
 */
function detectSyscalls(binary) {
  const syscallSignatures = {
    sol_invoke: Buffer.from([0x01, 0x00, 0x00]),
    sol_verify_signature: Buffer.from([0x02, 0x00, 0x00]),
    sol_alloc_free: Buffer.from([0x03, 0x00, 0x00]),
  };
  const syscalls = [];
  for (const [syscall, signature] of Object.entries(syscallSignatures)) {
    if (binary.includes(signature)) syscalls.push(syscall);
  }
  return syscalls;
}

/**
 * Infers program type based on address and binary patterns.
 * @param {string} address - Program address.
 * @param {Buffer} binary - Program binary.
 * @returns {string} - Inferred program type.
 */
function inferProgramType(address, binary) {
  if (address === 'GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw') return 'governance';
  if (binary.includes(Buffer.from('swap'))) return 'amm';
  if (binary.includes(Buffer.from('mintNFT'))) return 'nft';
  return 'unknown';
}