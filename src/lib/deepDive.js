import chalk from 'chalk';

/**
 * Performs a deep dive analysis of a Solana program’s instructions.
 *
 * @param {Object} analysis - Binary analysis insights.
 * @param {Object} transactionData - Transaction data.
 * @returns {Promise<Object>} - Instruction frequency and anomalies.
 */
export async function deepDiveAnalysis(analysis, transactionData) {
  try {
    if (!analysis?.insights || !transactionData?.transactions) {
      throw new Error('Invalid input data for deep dive analysis');
    }

    const instructionFrequency = transactionData.transactions.reduce((acc, tx) => {
      tx.instructions.forEach(ix => {
        const opcode = ix.parsed?.type || 'unknown';
        acc[opcode] = (acc[opcode] || 0) + 1;
      });
      return acc;
    }, {});

    const anomalies = [];
    if (analysis.insights.instructions > 1000 && transactionData.economicInsights.transactionCount < 10) {
      anomalies.push({
        issue: 'High instruction count with low activity',
        details: 'May indicate dormant or complex logic',
      });
    }

    if (transactionData.economicInsights.transactionTypes.others.count > transactionData.economicInsights.transactionCount * 0.3) {
      anomalies.push({
        issue: 'High non-standard transactions',
        details: 'May indicate hidden logic',
      });
    }

    return {
      instructionFrequency,
      anomalies,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Deep dive analysis failed: ${err.message}`));
    return { instructionFrequency: {}, anomalies: [] };
  }
}