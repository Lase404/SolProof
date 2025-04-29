import { getRecentTransactions, getTokenMetadata, analyzeFees } from './transactions.js';
import { inferBehavior } from './ai.js';
import { fetchProgramBinary } from './fetcher.js';
import { analyzeBinary } from './analyzer.js';
import { assessSafety } from './safetyAssessor.js';
import { assessRisks } from './riskAssessor.js';
import { generateIDL } from './idlGenerator.js';
import { reconstructCallGraph } from './callGraph.js';
import { analyzeAuthorityHolders } from './authorityAnalyzer.js';
import { scanVulnerabilities } from './vulnerabilityScanner.js';
import { startMonitoring } from './monitor.js';
import { extractState } from './stateExtractor.js';
import { inferGovernance } from './governanceInferer.js';
import { analyzeUpdateHistory } from './updateAnalyzer.js';
import { quickCheck } from './quickCheck.js';
import { generateAuditReport } from './auditReport.js';
import { deepDiveAnalysis } from './deepDive.js';
import { predictRisk } from './riskPredictor.js';
import { traceInteractions } from './interactionTracer.js';
import { exportIdaScript } from './idaExporter.js';
import { visualizeGraph } from './graphVisualizer.js';

export {
  getRecentTransactions,
  getTokenMetadata,
  analyzeFees,
  inferBehavior,
  fetchProgramBinary,
  analyzeBinary,
  assessSafety,
  assessRisks,
  generateIDL,
  reconstructCallGraph,
  analyzeAuthorityHolders,
  scanVulnerabilities,
  startMonitoring,
  extractState,
  inferGovernance,
  analyzeUpdateHistory,
  quickCheck,
  generateAuditReport,
  deepDiveAnalysis,
  predictRisk,
  traceInteractions,
  exportIdaScript,
  visualizeGraph,
};