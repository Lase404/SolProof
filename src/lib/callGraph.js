import chalk from 'chalk';

/**
 * Reconstructs a call graph for a Solana program based on analysis and transactions.
 *
 * @param {Object} analysis - Binary analysis insights.
 * @param {Object} transactions - Transaction data.
 * @returns {Promise<Object>} - Call graph with nodes and edges.
 */
export async function reconstructCallGraph(analysis, transactions) {
  try {
    if (!analysis?.insights || !transactions?.transactions) {
      throw new Error('Invalid input data for call graph reconstruction');
    }

    const nodes = new Set([analysis.insights.address]);
    const edges = [];

    transactions.transactions.forEach(tx => {
      tx.instructions.forEach(ix => {
        if (ix.accounts && ix.accounts.length >= 2) {
          const from = ix.accounts[0].toBase58();
          const to = ix.accounts[1].toBase58();
          nodes.add(from);
          nodes.add(to);
          edges.push({
            from,
            to,
            action: tx.type,
            count: 1,
          });
        }
      });
    });

    return {
      nodes: Array.from(nodes),
      edges,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Call graph reconstruction failed: ${err.message}`));
    return { nodes: [], edges: [] };
  }
}