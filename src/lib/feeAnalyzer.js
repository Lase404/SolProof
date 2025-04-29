import pkg from '@solana/web3.js';

const { Connection, PublicKey } = pkg;

export async function analyzeFees(address, options = { limit: 100 }) {
  try {
    const connection = new Connection(process.env.QUICKNODE_RPC_URL, 'confirmed');
    const programId = new PublicKey(address);
    const signatures = await connection.getSignaturesForAddress(programId, {
      limit: options.limit
    });
    
    let totalFees = 0;
    const fees = [];
    
    for (const sig of signatures) {
      const tx = await connection.getParsedTransaction(sig.signature, {
        commitment: 'confirmed',
        maxSupportedTransactionVersion: 0
      });
      if (tx?.meta?.fee) {
        const fee = tx.meta.fee / 1e9;
        totalFees += fee;
        fees.push({ signature: sig.signature, fee });
      }
    }
    
    return {
      averageFee: fees.length ? totalFees / fees.length : 0,
      totalFees,
      transactionCount: fees.length
    };
  } catch (err) {
    throw new Error(`Failed to analyze fees: ${err.message}`);
  }
}