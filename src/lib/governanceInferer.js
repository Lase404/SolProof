import chalk from 'chalk';

/**
 * Infers governance and trust mechanisms for a Solana program.
 *
 * @param {Array} authorityInsights - Authority holder insights.
 * @param {Object} callGraph - Call graph data.
 * @returns {Promise<Object>} - Governance type, trust score, and details.
 */
export async function inferGovernance(authorityInsights, callGraph) {
  try {
    if (!authorityInsights || !callGraph) throw new Error('Invalid input data for governance inference');

    const governanceType = authorityInsights.length > 1 ? 'Decentralized' : 'Centralized';
    let trustScore = authorityInsights.length > 1 ? 70 : 50;
    const details = [];

    if (authorityInsights.length > 1) details.push('Multiple authorities detected');
    else details.push('Single authority detected');

    if (callGraph.edges.some(edge => edge.action === 'governance')) {
      details.push('Voting interactions observed');
      trustScore += 10;
    }

    return {
      type: governanceType,
      trustScore: Math.min(100, trustScore),
      details,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Governance inference failed: ${err.message}`));
    return { type: 'Unknown', trustScore: 50, details: [] };
  }
}