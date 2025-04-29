import chalk from 'chalk';

/**
 * Predicts future risks for a Solana program based on authority, transaction, and safety data.
 *
 * @param {Array} authorityInsights - Authority holder insights.
 * @param {Object} transactionData - Transaction data.
 * @param {Object} safetyAssessment - Safety assessment results.
 * @returns {Promise<Object>} - Risk likelihood, prediction, and factors.
 */
export async function predictRisk(authorityInsights, transactionData, safetyAssessment) {
  try {
    if (!authorityInsights || !transactionData?.economicInsights || !safetyAssessment) {
      throw new Error('Invalid input data for risk prediction');
    }

    let riskLikelihood = 30;
    const riskFactors = [];

    if (transactionData.economicInsights.transactionVolumeAnalysis.highVolatility) {
      riskFactors.push({
        issue: 'High transaction volume volatility',
        details: 'May indicate manipulative activity',
      });
      riskLikelihood += 20;
    }

    if (authorityInsights.length === 1) {
      riskFactors.push({
        issue: 'Single authority',
        details: 'Increases risk of malicious upgrades',
      });
      riskLikelihood += 15;
    }

    if (safetyAssessment.safetyScore < 50) {
      riskFactors.push({
        issue: 'Low safety score',
        details: 'Indicates multiple vulnerabilities',
      });
      riskLikelihood += 25;
    }

    return {
      riskLikelihood: Math.min(100, riskLikelihood),
      prediction: riskLikelihood > 70 ? 'High risk' : 'Low to moderate risk',
      riskFactors,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Risk prediction failed: ${err.message}`));
    return {
      riskLikelihood: 30,
      prediction: 'Low risk',
      riskFactors: [],
    };
  }
}