import chalk from 'chalk';

/**
 * Generates an IDL for a Solana program based on analysis and transaction data.
 *
 * @param {Object} analysis - Binary analysis insights.
 * @param {Object} transactionData - Transaction data.
 * @returns {Promise<Object>} - Generated IDL.
 */
export async function generateIDL(analysis, transactionData) {
  try {
    if (!analysis?.insights || !transactionData?.transactions) {
      throw new Error('Invalid input data for IDL generation');
    }

    const instructions = transactionData.transactions.map((tx, index) => ({
      name: tx.type === 'governance' ? `governanceInstruction${index}` : `instruction${index}`,
      args: tx.instructions.map((ix, i) => ({
        name: `arg${i}`,
        type: ix.parsed?.type || 'unknown',
      })),
      returns: 'void',
    }));

    return {
      version: '0.1.0',
      name: analysis.insights.suspectedType || 'unknown',
      instructions: instructions.slice(0, 5),
    };
  } catch (err) {
    console.warn(chalk.yellow(`IDL generation failed: ${err.message}`));
    return { version: '0.1.0', name: 'unknown', instructions: [] };
  }
}