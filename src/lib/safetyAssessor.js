import chalk from 'chalk';

/**
 * Assesses the safety of a Solana program based on analysis, authority, transaction, and call graph data.
 *
 * @param {Object} analysis - Binary analysis insights.
 * @param {Array} authorityInsights - Authority holder insights.
 * @param {Object} transactions - Transaction data.
 * @param {Object} callGraph - Call graph data.
 * @returns {Promise<Object>} - Safety score and risks.
 */
export async function assessSafety(analysis, authorityInsights, transactions, callGraph) {
  try {
    if (!analysis?.insights || !transactions?.economicInsights) {
      throw new Error('Invalid input data for safety assessment');
    }

    const risks = [];
    let safetyScore = 80;

    if (analysis.insights.hiddenMint) {
      risks.push({
        issue: 'Potential unchecked minting',
        implication: 'Risk of unauthorized token issuance',
        mitigation: 'Verify minting constraints',
      });
      safetyScore -= 20;
    }

    if (authorityInsights.length === 1) {
      risks.push({
        issue: 'Single authority',
        implication: 'Centralization risk',
        mitigation: 'Monitor authority actions',
      });
      safetyScore -= 10;
    }

    if (transactions.economicInsights.suspiciousVolume > transactions.economicInsights.totalVolumeSOL * 0.5) {
      risks.push({
        issue: 'High suspicious volume',
        implication: 'Potential laundering',
        mitigation: 'Trace top accounts',
      });
      safetyScore -= 15;
    }

    if (callGraph.edges.length > 50) {
      risks.push({
        issue: 'Complex interactions',
        implication: 'Increased risk of hidden logic',
        mitigation: 'Review call graph',
      });
      safetyScore -= 10;
    }

    return {
      safetyScore: Math.max(0, Math.min(100, safetyScore)),
      risks,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Safety assessment failed: ${err.message}`));
    return { safetyScore: 50, risks: [] };
  }
}