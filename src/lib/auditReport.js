import chalk from 'chalk';

/**
 * Generates a comprehensive audit report for a Solana program.
 *
 * @param {Object} analysis - Binary analysis insights.
 * @param {Array} authorityInsights - Authority holder insights.
 * @param {Object} transactionData - Transaction data.
 * @param {Object} callGraph - Call graph data.
 * @param {Array} vulnerabilities - Detected vulnerabilities.
 * @param {Object} safetyAssessment - Safety assessment results.
 * @returns {Promise<Object>} - Audit report.
 */
export async function generateAuditReport(
  analysis,
  authorityInsights,
  transactionData,
  callGraph,
  vulnerabilities,
  safetyAssessment
) {
  try {
    if (!analysis?.insights || !transactionData?.economicInsights || !safetyAssessment) {
      throw new Error('Invalid input data for audit report');
    }

    const riskBreakdown = {
      critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
      high: vulnerabilities.filter(v => v.severity === 'High').length + safetyAssessment.risks.filter(r => r.implication.includes('malicious')).length,
      moderate: vulnerabilities.filter(v => v.severity === 'Moderate').length + safetyAssessment.risks.filter(r => !r.implication.includes('malicious')).length,
      low: vulnerabilities.filter(v => v.severity === 'Low').length,
    };

    const executiveSummary = {
      safetyScore: safetyAssessment.safetyScore,
      riskLevel: safetyAssessment.safetyScore < 50 ? 'High' : safetyAssessment.safetyScore < 80 ? 'Moderate' : 'Low',
      programType: analysis.insights.suspectedType.toUpperCase(),
      keyFindings: [
        `Safety Score: ${safetyAssessment.safetyScore}/100`,
        `Vulnerabilities: ${vulnerabilities.length} (${riskBreakdown.high} High, ${riskBreakdown.moderate} Moderate)`,
        `Transaction Volume: ${transactionData.economicInsights.totalVolumeSOL.toFixed(4)} SOL`,
        `Authority Control: ${authorityInsights.length} ${authorityInsights.length === 1 ? 'single authority' : 'authorities'}`,
      ],
      riskScoreBreakdown: riskBreakdown,
    };

    const prioritizedRisks = [
      ...vulnerabilities.filter(v => v.severity === 'High').map(v => ({
        type: v.type,
        severity: v.severity,
        details: v.details,
        mitigation: v.mitigation,
      })),
      ...safetyAssessment.risks.filter(r => r.implication.includes('malicious')).map(r => ({
        type: r.issue,
        severity: 'High',
        details: r.implication,
        mitigation: r.mitigation,
      })),
      ...vulnerabilities.filter(v => v.severity === 'Moderate').map(v => ({
        type: v.type,
        severity: v.severity,
        details: v.details,
        mitigation: v.mitigation,
      })),
      ...safetyAssessment.risks.filter(r => !r.implication.includes('malicious')).map(r => ({
        type: r.issue,
        severity: 'Moderate',
        details: r.implication,
        mitigation: r.mitigation,
      })),
    ];

    const recommendations = [
      {
        priority: 'High',
        action: 'Monitor program updates on Solscan.',
        link: `https://solscan.io/account/${analysis.insights.address}#events`,
      },
      {
        priority: analysis.insights.suspectedType === 'governance' ? 'High' : 'Moderate',
        action: 'Verify governance or token logic on-chain.',
        link: `https://solscan.io/account/${analysis.insights.address}`,
      },
      {
        priority: vulnerabilities.length > 0 ? 'High' : 'Moderate',
        action: 'Address detected vulnerabilities.',
        link: null,
      },
    ];

    return {
      programAddress: analysis.insights.address,
      timestamp: new Date().toISOString(),
      executiveSummary,
      riskAssessment: { prioritizedRisks, riskScoreBreakdown: riskBreakdown, totalRisks: prioritizedRisks.length },
      binaryAnalysis: {
        size: analysis.insights.instructions * 8,
        instructionCount: analysis.insights.instructions,
        syscalls: analysis.insights.syscalls,
        likelyBehavior: analysis.insights.suspectedType,
        controlFlow: {
          branches: analysis.insights.controlFlow.branches,
          loops: analysis.insights.controlFlow.loops,
          complexity: analysis.insights.controlFlow.branches + analysis.insights.controlFlow.loops > 70 ? 'High' : 'Moderate',
        },
        dependencies: callGraph.nodes.filter(node => node !== analysis.insights.address),
      },
      economicAnalysis: {
        totalVolumeSOL: transactionData.economicInsights.totalVolumeSOL.toFixed(4),
        averageFeeSOL: transactionData.economicInsights.averageFeeSOL.toFixed(6),
        transactionCount: transactionData.economicInsights.transactionCount,
        transactionTypes: transactionData.economicInsights.transactionTypes,
        suspiciousVolumeSOL: transactionData.economicInsights.suspiciousVolume.toFixed(4),
        tokenFlows: transactionData.economicInsights.tokenFlowInsights,
      },
      authorityAnalysis: authorityInsights,
      callGraphAnalysis: {
        nodes: callGraph.nodes,
        edges: callGraph.edges,
        interactionComplexity: callGraph.edges.length > 50 ? 'High' : callGraph.edges.length > 20 ? 'Moderate' : 'Low',
      },
      vulnerabilityAnalysis: vulnerabilities,
      safetyAnalysis: {
        safetyScore: safetyAssessment.safetyScore,
        feedback: safetyAssessment.risks,
      },
      recommendations,
      metadata: { version: '1.0.0', generatedBy: 'SolProof SDK', generationTime: new Date().toISOString(), solanaNetwork: 'mainnet' },
    };
  } catch (err) {
    console.warn(chalk.yellow(`Audit report generation failed: ${err.message}`));
    return {
      programAddress: analysis?.insights?.address || 'unknown',
      timestamp: new Date().toISOString(),
      executiveSummary: { safetyScore: 50, riskLevel: 'Moderate', programType: 'Unknown', keyFindings: [], riskScoreBreakdown: { critical: 0, high: 0, moderate: 0, low: 0 } },
      riskAssessment: { prioritizedRisks: [], riskScoreBreakdown: { critical: 0, high: 0, moderate: 0, low: 0 }, totalRisks: 0 },
      binaryAnalysis: { size: 0, instructionCount: 0, syscalls: [], likelyBehavior: 'unknown', controlFlow: { branches: 0, loops: 0, complexity: 'Low' }, dependencies: [] },
      economicAnalysis: { totalVolumeSOL: '0.0000', averageFeeSOL: '0.000000', transactionCount: 0, transactionTypes: {}, suspiciousVolumeSOL: '0.0000', tokenFlows: { topInflows: [], topOutflows: [], concentrationRisk: false } },
      authorityAnalysis: [],
      callGraphAnalysis: { nodes: [], edges: [], interactionComplexity: 'Low' },
      vulnerabilityAnalysis: [],
      safetyAnalysis: { safetyScore: 50, feedback: [] },
      recommendations: [],
      metadata: { version: '1.0.0', generatedBy: 'SolProof SDK', generationTime: new Date().toISOString(), solanaNetwork: 'mainnet' },
    };
  }
}