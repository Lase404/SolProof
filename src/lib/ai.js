import chalk from 'chalk';

/**
 * Infers the behavior of a Solana program, estimating scam probability, laundering likelihood,
 * and program type based on binary and transaction data.
 *
 * @param {Object} analysis - Binary analysis insights from analyzer.js.
 * @param {Object} transactionData - Transaction data from transactions.js.
 * @returns {Promise<Object>} - Behavior inference results with scamProbability, launderingLikelihood, and programTypeConfidence.
 */
export async function inferBehavior(analysis, transactionData) {
  try {
    if (!analysis?.insights || !transactionData?.economicInsights) {
      throw new Error('Invalid input data for behavior inference');
    }

    const { insights } = analysis;
    const { economicInsights } = transactionData;

    // Scam Probability
    let scamProbability = 10; // Base probability
    if (insights.hiddenMint) scamProbability += 30;
    if (economicInsights.suspiciousVolume > economicInsights.totalVolumeSOL * 0.5) scamProbability += 20;
    if (economicInsights.transactionCount < 10 && economicInsights.totalVolumeSOL > 100) scamProbability += 20;
    if (insights.authorityHolders.length === 1) scamProbability += 10;

    // Laundering Likelihood
    let launderingLikelihood = 10;
    if (economicInsights.tokenFlowInsights.concentrationRisk) launderingLikelihood += 25;
    if (economicInsights.transactionVolumeAnalysis.highVolatility) launderingLikelihood += 20;
    if (economicInsights.transactionTypes.others.count > economicInsights.transactionCount * 0.3) launderingLikelihood += 15;
    if (insights.syscalls.includes('sol_invoke') && insights.instructions > 500) launderingLikelihood += 10;

    // Program Type Confidence
    let programTypeConfidence = {};
    if (insights.suspectedType === 'governance') {
      programTypeConfidence = { governance: 90, amm: 5, nft: 5 };
    } else if (economicInsights.transactionTypes.swaps.count > economicInsights.transactionCount * 0.5) {
      programTypeConfidence = { amm: 85, governance: 10, nft: 5 };
    } else if (economicInsights.transactionTypes.nftMints.count > economicInsights.transactionCount * 0.3) {
      programTypeConfidence = { nft: 80, amm: 10, governance: 10 };
    } else {
      programTypeConfidence = { unknown: 50, governance: 20, amm: 20, nft: 10 };
    }

    return {
      scamProbability: Math.min(100, scamProbability),
      launderingLikelihood: Math.min(100, launderingLikelihood),
      programTypeConfidence,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Behavior inference failed: ${err.message}`));
    return {
      scamProbability: 10,
      launderingLikelihood: 10,
      programTypeConfidence: { unknown: 100 },
    };
  }
}