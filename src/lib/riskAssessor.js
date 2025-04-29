import chalk from 'chalk';

/**
 * Assesses risks for a Solana program based on analysis and vulnerabilities.
 *
 * @param {Object} analysis - Binary analysis insights.
 * @param {Array} vulnerabilities - Detected vulnerabilities.
 * @param {string} address - Program address.
 * @returns {Promise<Array>} - List of risks.
 */
export async function assessRisks(analysis, vulnerabilities, address) {
  try {
    if (!analysis?.insights) throw new Error('Invalid analysis insights');

    const risks = vulnerabilities.map(vuln => ({
      issue: `Vulnerability: ${vuln.type}`,
      implication: vuln.details,
      mitigation: `Address ${vuln.severity} issue`,
    }));

    if (analysis.insights.reentrancyRisk === 'Moderate' || analysis.insights.reentrancyRisk === 'High') {
      risks.push({
        issue: 'Potential reentrancy risk',
        implication: 'May allow unauthorized state changes',
        mitigation: 'Audit for reentrancy guards',
      });
    }

    if (analysis.insights.instructions > 1000) {
      risks.push({
        issue: 'High instruction count',
        implication: 'Increased complexity may hide bugs',
        mitigation: 'Conduct deep dive analysis',
      });
    }

    return risks;
  } catch (err) {
    console.warn(chalk.yellow(`Risk assessment failed for ${address}: ${err.message}`));
    return [];
  }
}