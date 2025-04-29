
export async function predictRisk(authorityInsights, transactionData, safetyAssessment) {
  try {
    let riskLikelihood = 50;
    const riskFactors = [];

    if (safetyAssessment.safetyScore < 50) {
      riskLikelihood += 20;
      riskFactors.push({ issue: 'Low Safety Score', details: 'Program has high risk of scams or bugs' });
    }

    if (transactionData.economicInsights.suspiciousVolume > 0.1) {
      riskLikelihood += 15;
      riskFactors.push({ issue: 'Suspicious Volume', details: 'High volume of non-standard transactions' });
    }

    if (authorityInsights.some(auth => auth.warnings.length > 0)) {
      riskLikelihood += 10;
      riskFactors.push({ issue: 'Authority Warnings', details: 'Authority holders have suspicious activity' });
    }

    return {
      riskLikelihood: Math.min(100, riskLikelihood),
      prediction: riskLikelihood > 70 ? 'High risk of future scams or laundering' : riskLikelihood > 40 ? 'Moderate risk, monitor closely' : 'Low risk, but verify',
      riskFactors,
    };
  } catch (err) {
    throw new Error(`Risk prediction failed: ${err.message}`);
  }
}