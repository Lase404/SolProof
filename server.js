import express from 'express';
import { WebSocketServer } from 'ws';
import dotenv from 'dotenv';
import chalk from 'chalk';
import axios from 'axios';
import Bottleneck from 'bottleneck';
import NodeCache from 'node-cache';
import Table from 'cli-table3';
import { PublicKey, Connection } from '@solana/web3.js';
import {
  fetchProgramBinary,
  analyzeBinary,
  getRecentTransactions,
  inferBehavior,
  assessSafety,
  analyzeFees,
  reconstructCallGraph,
  analyzeAuthorityHolders,
  scanVulnerabilities,
  startMonitoring,
  extractState,
  generateIDL,
  inferGovernance,
  analyzeUpdateHistory,
  quickCheck,
  generateAuditReport,
  deepDiveAnalysis,
  predictRisk,
  traceInteractions,
  exportIdaScript,
  visualizeGraph,
} from './lib/index.js';
import { success, error } from './utils/formatting.js';

dotenv.config();

const RENDER_API_URL = 'https://solproof-sdk.onrender.com';
const app = express();
app.use(express.json());
const PORT = process.env.PORT || 3000;
const wss = new WebSocketServer({ noServer: true });
const cache = new NodeCache({ stdTTL: 300 });
let solPriceUSD = 150;

const limiter = new Bottleneck({
  maxConcurrent: 10,
  minTime: 1000 / 5,
  reservoir: 50,
  reservoirRefreshAmount: 50,
  reservoirRefreshInterval: 60 * 1000,
});

app.use((req, res, next) => {
  limiter.schedule(() => {
    next();
  }).catch(() => {
    res.status(429).json({ error: 'Too many requests.', support: 'support@solproof.org' });
  });
});

async function proxyToRender(req, res, endpoint, method = 'post') {
  try {
    const response = await axios({
      method,
      url: `${RENDER_API_URL}${endpoint}`,
      data: req.body,
      params: req.query,
    });
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: `Proxy failed: ${err.message}`, support: 'support@solproof.org' });
  }
}

async function fetchSolPrice() {
  const cacheKey = 'solPriceUSD';
  const cachedPrice = cache.get(cacheKey);
  if (cachedPrice) {
    solPriceUSD = cachedPrice;
    return;
  }
  try {
    const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd');
    const data = await response.json();
    solPriceUSD = data.solana.usd;
    cache.set(cacheKey, solPriceUSD);
    console.log(chalk.green(`SOL Price: $${solPriceUSD} [Success]`));
  } catch (err) {
    console.log(chalk.yellow(`Failed to fetch SOL price: ${err.message}. Using default $150.`));
  }
}

function validateAddress(address) {
  try {
    new PublicKey(address);
    return true;
  } catch (err) {
    return false;
  }
}

async function withTimeout(fn, ms, fallback) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ms);
  try {
    const result = await fn({ signal: controller.signal });
    clearTimeout(timeout);
    return result;
  } catch (err) {
    clearTimeout(timeout);
    console.log(chalk.yellow(`[DEBUG] Operation timed out or failed: ${err.message}`));
    return fallback;
  }
}

function tableToJson(table) {
  const headers = table.options.head.map(h => String(h).replace(/\x1B\[\d+m/g, ''));
  return table.map(row =>
    headers.reduce((obj, header, i) => {
      const value = row[i] === null || row[i] === undefined ? 'N/A' : String(row[i]).replace(/\x1B\[\d+m/g, '');
      obj[header] = value;
      return obj;
    }, {})
  );
}

const validateAddressMiddleware = (req, res, next) => {
  const address = req.params.address || req.body.address;
  if (!address || !validateAddress(address)) {
    return res.status(400).json({
      error: `Invalid program address: ${address || 'missing'}`,
      message: 'Please provide a valid Solana address.',
      support: 'adunbi8@gmail.com',
    });
  }
  next();
};

// API Endpoints
// Initialize SOL price on server start
app.get('/init', async (req, res) => {
  await fetchSolPrice();
  res.json({ status: 'success', solPriceUSD });
});

// Analyze program
app.post('/analyze/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [], economicInsights: { totalVolumeSOL: 0, suspiciousVolume: 0, transactionTypes: {}, topAccounts: [] } });
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0, syscalls: [], reentrancyRisk: 'Low', controlFlow: { branches: 0, loops: 0 }, usesBorsh: false, authorityHolders: [] } });
    const behavior = await withTimeout(signal => inferBehavior(analysis, transactionData, { signal }), 5000, { scamProbability: 20, launderingLikelihood: 10, suspectedType: analysis.insights.suspectedType });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const vulnerabilities = await withTimeout(signal => scanVulnerabilities(analysis, { signal }), 5000, []);
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
    const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 50, risks: [] });

    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY}`, 'confirmed');
    const accountInfo = await withTimeout(signal => connection.getAccountInfo(new PublicKey(address), { signal }), 5000, null);

    // Format tables with string-friendly values
    const overviewTable = new Table({ head: ['Metric', 'Value'] });
    overviewTable.push(
      ['Safety Score', String(safetyAssessment.safetyScore) + `/100 (${safetyAssessment.safetyScore < 50 ? 'High Risk' : safetyAssessment.safetyScore < 80 ? 'Moderate Risk' : 'Low Risk'})`],
      ['Scam Probability', String(behavior.scamProbability) + `% (${behavior.scamProbability < 30 ? 'Low' : behavior.scamProbability < 70 ? 'Moderate' : 'High'})`],
      ['Laundering Risk', String(behavior.launderingLikelihood) + `% (${behavior.launderingLikelihood < 30 ? 'Low' : behavior.launderingLikelihood < 70 ? 'Moderate' : 'High'})`],
      ['Total Volume', transactionData.economicInsights.totalVolumeSOL.toFixed(4) + ` SOL (~$${Number(transactionData.economicInsights.totalVolumeSOL * solPriceUSD).toFixed(2)} at $${solPriceUSD}/SOL)`],
      ['Suspicious Volume', transactionData.economicInsights.suspiciousVolume.toFixed(4) + ` SOL (~$${Number(transactionData.economicInsights.suspiciousVolume * solPriceUSD).toFixed(2)})`]
    );

    const accountTable = new Table({ head: ['Metric', 'Value'] });
    accountTable.push(
      ['Balance', accountInfo ? (accountInfo.lamports / 1e9).toFixed(4) + ' SOL' : '0.0000 SOL'],
      ['Data Length', String(binary.length) + ' bytes'],
      ['Owner', accountInfo?.owner ? accountInfo.owner.toBase58().slice(0, 20) + '...' : 'Unknown'],
      ['Executable', accountInfo?.executable ? 'Yes' : 'No']
    );

    const txBreakdownTable = new Table({ head: ['Type', 'Count', 'Volume (SOL)', 'Approx. Value (USD)'] });
    const txTypes = transactionData.economicInsights.transactionTypes || {};
    txBreakdownTable.push(
      ['Swaps', String(txTypes.swap?.count || 0), (txTypes.swap?.volume || 0).toFixed(4), `$${Number(txTypes.swap?.volume * solPriceUSD || 0).toFixed(2)}`],
      ['Transfers', String(txTypes.transfer?.count || 0), (txTypes.transfer?.volume || 0).toFixed(4), `$${Number(txTypes.transfer?.volume * solPriceUSD || 0).toFixed(2)}`],
      ['Mints', String(txTypes.mint?.count || 0), (txTypes.mint?.volume || 0).toFixed(4), `$${Number(txTypes.mint?.volume * solPriceUSD || 0).toFixed(2)}`],
      ['Burns', String(txTypes.burn?.count || 0), (txTypes.burn?.volume || 0).toFixed(4), `$${Number(txTypes.burn?.volume * solPriceUSD || 0).toFixed(2)}`],
      ['Governance', String(txTypes.governance?.count || 0), (txTypes.governance?.volume || 0).toFixed(4), `$${Number(txTypes.governance?.volume * solPriceUSD || 0).toFixed(2)}`],
      ['NFT Mints', String(txTypes.nftMint?.count || 0), (txTypes.nftMint?.volume || 0).toFixed(4), `$${Number(txTypes.nftMint?.volume * solPriceUSD || 0).toFixed(2)}`],
      ['Custom/Other', String(txTypes.others?.count || 0), (txTypes.others?.volume || 0).toFixed(4), `$${Number(txTypes.others?.volume * solPriceUSD || 0).toFixed(2)}`]
    );

    const vulnTable = new Table({ head: ['Type', 'Severity', 'Details', 'Confidence'] });
    vulnerabilities.forEach(vuln => vulnTable.push([String(vuln.type), String(vuln.severity), String(vuln.details), String(vuln.confidence) + '%']));

    const authorityTable = new Table({ head: ['Authority', 'Total SOL Withdrawn', 'Wallet Age', 'Token Mints'] });
    authorityInsights.forEach(auth => authorityTable.push([String(auth.authority).slice(0, 8) + '...', auth.totalSOLWithdrawn.toFixed(4) + ' SOL', String(auth.walletAgeDays) + ' days', String(auth.tokenMintCount)]));

    const callGraphTable = new Table({ head: ['From', 'To', 'Action', 'Count'] });
    callGraph.edges.slice(0, 5).forEach(edge => callGraphTable.push([String(edge.from).slice(0, 8) + '...', String(edge.to).slice(0, 8) + '...', String(edge.action || 'unknown'), String(edge.count)]));

    res.json({
      status: 'success',
      data: {
        overview: tableToJson(overviewTable),
        account: tableToJson(accountTable),
        transactions: tableToJson(txBreakdownTable),
        moneyMovement: {
          totalVolume: transactionData.economicInsights.totalVolumeSOL.toFixed(4) + ' SOL',
          suspiciousVolume: transactionData.economicInsights.suspiciousVolume.toFixed(4) + ' SOL',
          topAccounts: transactionData.economicInsights.topAccounts?.slice(0, 3).map(acc => ({
            address: String(acc.address),
            volume: acc.volume.toFixed(4),
            action: String(acc.action),
            txCount: String(acc.txCount),
            solscan: `https://solscan.io/account/${acc.address}`,
          })) || [],
        },
        binaryInsights: {
          instructions: String(analysis.insights.instructions),
          syscalls: analysis.insights.syscalls.map(String),
          suspectedType: String(analysis.insights.suspectedType),
          reentrancyRisk: String(analysis.insights.reentrancyRisk),
          controlFlow: {
            branches: String(analysis.insights.controlFlow.branches),
            loops: String(analysis.insights.controlFlow.loops),
          },
          usesBorsh: String(analysis.insights.usesBorsh),
        },
        safetyAssessment: {
          safetyScore: String(safetyAssessment.safetyScore),
          risks: safetyAssessment.risks.map(r => ({ type: String(r.type), details: String(r.details) })),
        },
        vulnerabilities: tableToJson(vulnTable),
        authorities: tableToJson(authorityTable),
        callGraph: tableToJson(callGraphTable),
        recommendations: [
          `Monitor program updates: https://solscan.io/account/${address}#events`,
          'Run `audit-report` for a detailed report.',
        ],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Analysis failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Analyze fees
app.post('/analyze-fees/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  const { limit = 25 } = req.body;
  try {
    const feeAnalysis = await withTimeout(signal => analyzeFees(address, { limit: parseInt(limit), signal }), 5000, { totalTransactions: 0, averageFeeSOL: 0.000005, hiddenFees: [], manipulation: [] });

    const feeTable = new Table({ head: ['Metric', 'Value'] });
    feeTable.push(
      ['Total Transactions', String(feeAnalysis.totalTransactions || 0)],
      ['Average Fee (SOL)', feeAnalysis.averageFeeSOL?.toFixed(6) || '0.000005'],
      ['Average Fee (USD)', `$${Number(feeAnalysis.averageFeeSOL * solPriceUSD || 0.000005 * solPriceUSD).toFixed(4)}`],
      ['Hidden Fees Detected', String(feeAnalysis.hiddenFees?.length || 0)],
      ['Manipulation Issues', String(feeAnalysis.manipulation?.length || 0)]
    );

    const manipulationTable = new Table({ head: ['Issue', 'Signature', 'Details'] });
    feeAnalysis.manipulation?.forEach(issue => manipulationTable.push([String(issue.issue), String(issue.signature)?.slice(0, 8) + '...' || 'N/A', String(issue.details)]));

    res.json({
      status: 'success',
      data: {
        fees: tableToJson(feeTable),
        manipulationIssues: tableToJson(manipulationTable),
        recommendations: [
          `Monitor fees: https://solscan.io/account/${address}#transactions`,
          'Run `audit-report` for a comprehensive report.',
        ],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Fee analysis failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Quick check
app.get('/quick-check/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const result = await withTimeout(signal => quickCheck(address, { signal }), 5000, { isActive: false, lastTransaction: null, isUpgradeable: false, upgradeAuthority: null, basicSafetyScore: 50 });

    const quickTable = new Table({ head: ['Metric', 'Value'] });
    quickTable.push(
      ['Program Active', String(result.isActive ? 'Yes' : 'No')],
      ['Recent Activity', result.lastTransaction ? new Date(result.lastTransaction * 1000).toISOString() : 'None'],
      ['Upgradeable', String(result.isUpgradeable ? 'Yes' : 'No')],
      ['Upgrade Authority', result.upgradeAuthority ? String(result.upgradeAuthority).slice(0, 8) + '...' : 'None'],
      ['Safety Score', String(result.basicSafetyScore) + '/100']
    );

    res.json({
      status: 'success',
      data: {
        quickCheck: tableToJson(quickTable),
        recommendations: ['Run `analyze` for detailed analysis.', 'Run `monitor` to track activity.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Quick check failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Monitor (WebSocket)
wss.on('connection', (ws, req) => {
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const address = urlParams.get('address');
  const threshold = parseInt(urlParams.get('threshold') || '1000000000');

  if (!validateAddress(address)) {
    ws.send(JSON.stringify({
      error: `Invalid program address: ${address}`,
      support: 'support@solproof.org',
    }));
    ws.close();
    return;
  }

  startMonitoring(address, { threshold, commitment: 'confirmed' })
    .then(() => {
      ws.send(JSON.stringify({
        status: 'success',
        message: `Monitoring ${address.slice(0, 8)}... for transactions above ${(threshold / 1e9).toFixed(2)} SOL`,
      }));
    })
    .catch(err => {
      ws.send(JSON.stringify({
        error: `Monitoring failed: ${err.message}`,
        debug: err.stack,
        support: 'support@solproof.org',
      }));
      ws.close();
    });

  ws.on('close', () => {
    console.log(chalk.yellow(`WebSocket client disconnected for ${address.slice(0, 8)}...`));
  });
});

// Extract state
app.get('/extract-state/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const state = await withTimeout(signal => extractState(address, { signal }), 5000, []);

    const stateTable = new Table({ head: ['Account', 'Lamports', 'Data Length', 'Data (Hex)'] });
    state.forEach(account => stateTable.push([String(account.account).slice(0, 8) + '...', String(account.lamports), String(account.dataLength), String(account.data).slice(0, 20) + (account.data.length > 20 ? '...' : '')]));

    res.json({
      status: 'success',
      data: {
        state: tableToJson(stateTable),
        recommendations: ['Run `analyze` for detailed analysis.', 'Run `reconstruct-api` to infer program structure.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `State extraction failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Reconstruct API
app.get('/reconstruct-api/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const idl = await withTimeout(signal => generateIDL(analysis, transactionData, { signal }), 5000, { instructions: [] });

    const idlTable = new Table({ head: ['Instruction', 'Arguments', 'Returns'] });
    idl.instructions.forEach(instruction => idlTable.push([String(instruction.name), instruction.args.map(arg => `${arg.name}: ${arg.type}`).join(', ') || 'None', String(instruction.returns || 'void')]));

    res.json({
      status: 'success',
      data: {
        idl: tableToJson(idlTable),
        recommendations: ['Run `export-idl` to save the IDL.', 'Run `deep-dive` to analyze instructions.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `API reconstruction failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Infer governance
app.get('/infer-governance/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { authorityHolders: [] } });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
    const governance = await withTimeout(signal => inferGovernance(authorityInsights, callGraph, { signal }), 5000, { type: 'Unknown', trustScore: 50, details: [] });

    const govTable = new Table({ head: ['Metric', 'Value'] });
    govTable.push(
      ['Governance Type', String(governance.type)],
      ['Trust Score', String(governance.trustScore) + `/100 (${governance.trustScore < 50 ? 'Low' : governance.trustScore < 80 ? 'Moderate' : 'High'})`],
      ['Details', governance.details.map(String).join('; ') || 'None']
    );

    res.json({
      status: 'success',
      data: {
        governance: tableToJson(govTable),
        recommendations: ['Run `audit-report` for detailed governance report.', 'Run `trace-interactions` to monitor authority activity.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Governance inference failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Update history
app.get('/update-history/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const updates = await withTimeout(signal => analyzeUpdateHistory(address, { signal }), 5000, []);

    const updateTable = new Table({ head: ['Timestamp', 'Changes'] });
    updates.forEach(update => updateTable.push([new Date(update.timestamp * 1000).toISOString(), update.changes.map(String).join(', ') || 'None']));

    res.json({
      status: 'success',
      data: {
        updates: tableToJson(updateTable),
        recommendations: ['Run `monitor` to track future updates.', 'Run `audit-report` for a comprehensive report.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Update history analysis failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Audit report
app.post('/audit-report/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  const { output = 'audit_report.json', format = 'json' } = req.body;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', authorityHolders: [] } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [], economicInsights: { totalVolumeSOL: 0, suspiciousVolume: 0, topAccounts: [] } });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const vulnerabilities = await withTimeout(signal => scanVulnerabilities(analysis, { signal }), 5000, []);
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
    const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 50, risks: [] });
    const report = await withTimeout(signal => generateAuditReport(analysis, authorityInsights, transactionData, callGraph, vulnerabilities, safetyAssessment, { signal }), 5000, {
      programAddress: address,
      executiveSummary: { programType: 'UNKNOWN', safetyScore: 50, riskLevel: 'Moderate', keyFindings: [], riskScoreBreakdown: { critical: 0, high: 0, moderate: 0, low: 0 } },
      riskAssessment: { totalRisks: 0, prioritizedRisks: [] },
      binaryAnalysis: { size: 0, instructionCount: 0, syscalls: [], likelyBehavior: 'Unknown', controlFlow: { complexity: 0, branches: 0, loops: 0 } },
      economicAnalysis: { totalVolumeSOL: 0, averageFeeSOL: 0, suspiciousVolumeSOL: 0 },
      vulnerabilityAnalysis: [],
      recommendations: [],
    });

    const summaryTable = new Table({ head: ['Metric', 'Value'] });
    summaryTable.push(
      ['Program Address', String(report.programAddress)],
      ['Program Type', String(report.executiveSummary.programType)],
      ['Safety Score', String(report.executiveSummary.safetyScore) + '/100'],
      ['Risk Level', String(report.executiveSummary.riskLevel)],
      ['Total Risks', String(report.riskAssessment.totalRisks)],
      ['Vulnerabilities', String(report.vulnerabilityAnalysis.length)]
    );

    res.json({
      status: 'success',
      data: {
        summary: tableToJson(summaryTable),
        keyFindings: report.executiveSummary.keyFindings.map(String),
        report: format === 'json' ? report : {
          markdown: [
            `# SolProof Audit Report`,
            `**Program Address**: ${report.programAddress}`,
            `**Timestamp**: ${report.timestamp || new Date().toISOString()}`,
            `**Program Type**: ${report.executiveSummary.programType}`,
            `## Executive Summary`,
            `- **Safety Score**: ${report.executiveSummary.safetyScore}/100`,
            `- **Risk Level**: ${report.executiveSummary.riskLevel}`,
            `- **Key Findings**:`,
            ...report.executiveSummary.keyFindings.map(f => `  - ${f}`),
            `- **Risk Breakdown**: ${report.executiveSummary.riskScoreBreakdown.critical} Critical, ${report.executiveSummary.riskScoreBreakdown.high} High, ${report.executiveSummary.riskScoreBreakdown.moderate} Moderate, ${report.executiveSummary.riskScoreBreakdown.low} Low`,
            `## Risk Assessment`,
            ...report.riskAssessment.prioritizedRisks.map(r => `- **${r.type}** (${r.severity}): ${r.details}\n  - Mitigation: ${r.mitigation}`),
            `## Binary Analysis`,
            `- **Size**: ${report.binaryAnalysis.size} bytes`,
            `- **Instructions**: ${report.binaryAnalysis.instructionCount}`,
            `- **Syscalls**: ${report.binaryAnalysis.syscalls.join(', ') || 'None'}`,
            `- **Behavior**: ${report.binaryAnalysis.likelyBehavior}`,
            `- **Control Flow**: ${report.binaryAnalysis.controlFlow.complexity} (Branches: ${report.binaryAnalysis.controlFlow.branches}, Loops: ${report.binaryAnalysis.controlFlow.loops})`,
            `## Economic Analysis`,
            `- **Total Volume**: ${report.economicAnalysis.totalVolumeSOL} SOL`,
            `- **Average Fee**: ${report.economicAnalysis.averageFeeSOL} SOL`,
            `- **Suspicious Volume**: ${report.economicAnalysis.suspiciousVolumeSOL} SOL`,
            `## Recommendations`,
            ...report.recommendations.map(r => `- **${r.priority}**: ${r.action}${r.link ? ` [${r.link}]` : ''}`),
          ].join('\n'),
        },
        recommendations: ['Run `deep-dive` to investigate risks.', 'Run `monitor` to track changes.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Audit report generation failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Deep dive
app.get('/deep-dive/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { instructions: 0 } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const deepDive = await withTimeout(signal => deepDiveAnalysis(analysis, transactionData, { signal }), 5000, { instructionFrequency: {}, anomalies: [] });

    const freqTable = new Table({ head: ['Instruction', 'Frequency'] });
    Object.entries(deepDive.instructionFrequency).forEach(([opcode, count]) => freqTable.push([String(opcode), String(count)]));

    const anomalyTable = new Table({ head: ['Issue', 'Details'] });
    deepDive.anomalies.forEach(anomaly => anomalyTable.push([String(anomaly.issue), String(anomaly.details)]));

    res.json({
      status: 'success',
      data: {
        instructionFrequency: tableToJson(freqTable),
        anomalies: tableToJson(anomalyTable),
        recommendations: ['Run `export-ida` to analyze instructions in IDA Pro.', 'Run `audit-report` for a comprehensive report.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Deep dive analysis failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Predict risk
app.get('/predict-risk/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { authorityHolders: [] } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
    const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 50, risks: [] });
    const riskPrediction = await withTimeout(signal => predictRisk(authorityInsights, transactionData, safetyAssessment, { signal }), 5000, { riskLikelihood: 50, prediction: 'Moderate risk', riskFactors: [] });

    const riskTable = new Table({ head: ['Metric', 'Value'] });
    riskTable.push(
      ['Risk Likelihood', String(riskPrediction.riskLikelihood) + '%'],
      ['Prediction', String(riskPrediction.prediction)]
    );

    const factorTable = new Table({ head: ['Issue', 'Details'] });
    riskPrediction.riskFactors?.forEach(factor => factorTable.push([String(factor.issue), String(factor.details)]));

    res.json({
      status: 'success',
      data: {
        risk: tableToJson(riskTable),
        riskFactors: tableToJson(factorTable),
        recommendations: ['Run `monitor` to track high-risk activities.', 'Run `audit-report` for a comprehensive report.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Risk prediction failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Trace interactions
app.get('/trace-interactions/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  try {
    const interactions = await withTimeout(signal => traceInteractions(address, { signal }), 5000, []);

    const interactionTable = new Table({ head: ['Account', 'Action', 'Volume (SOL)', 'Timestamp'] });
    interactions.forEach(ix => interactionTable.push([String(ix.caller)?.slice(0, 8) + '...' || 'N/A', String(ix.action || 'unknown'), ix.volume?.toFixed(4) || '0.0000', ix.timestamp ? new Date(ix.timestamp).toISOString() : 'N/A']));

    res.json({
      status: 'success',
      data: {
        interactions: tableToJson(interactionTable),
        recommendations: ['Run `monitor` to track ongoing interactions.', 'Run `analyze` for detailed program analysis.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Interaction tracing failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Compare programs
app.post('/compare', async (req, res) => {
  const { address1, address2 } = req.body;
  if (!validateAddress(address1) || !validateAddress(address2)) {
    return res.status(400).json({
      error: `Invalid program address: ${!validateAddress(address1) ? address1 : address2}`,
      message: 'Please provide valid Solana addresses.',
      support: 'support@solproof.org',
    });
  }

  try {
    const [binary1, binary2] = await Promise.all([
      withTimeout(signal => fetchProgramBinary(address1, { signal }), 5000, Buffer.from([])),
      withTimeout(signal => fetchProgramBinary(address2, { signal }), 5000, Buffer.from([])),
    ]);
    const [analysis1, analysis2] = await Promise.all([
      withTimeout(signal => analyzeBinary(binary1, address1, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } }),
      withTimeout(signal => analyzeBinary(binary2, address2, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } }),
    ]);

    const compareTable = new Table({ head: ['Metric', 'Program 1', 'Program 2'] });
    compareTable.push(
      ['Program Type', String(analysis1.insights.suspectedType), String(analysis2.insights.suspectedType)],
      ['Instruction Count', String(analysis1.insights.instructions), String(analysis2.insights.instructions)],
      ['Binary Size', String(binary1.length) + ' bytes', String(binary2.length) + ' bytes'],
      ['Reentrancy Risk', String(analysis1.insights.reentrancyRisk || 'Low'), String(analysis2.insights.reentrancyRisk || 'Low')]
    );

    res.json({
      status: 'success',
      data: {
        comparison: tableToJson(compareTable),
        recommendations: ['Run `analyze` on each program for detailed insights.', 'Run `audit-report` for comprehensive reports.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Comparison failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Export IDL
app.post('/export-idl/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  const { output = 'idl.json' } = req.body;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const idl = await withTimeout(signal => generateIDL(analysis, transactionData, { signal }), 5000, { instructions: [] });

    res.json({
      status: 'success',
      data: {
        idl,
        output,
        recommendations: ['Use IDL with Anchor for program interaction.', 'Run `deep-dive` to analyze instructions.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `IDL export failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Export IDA script
app.post('/export-ida/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  const { output = 'ida_script.py' } = req.body;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0, syscalls: [] } });
    const script = await withTimeout(signal => exportIdaScript(analysis, { signal }), 5000, '# SolProof IDA Pro Script\nprint("No instructions to analyze")');

    res.json({
      status: 'success',
      data: {
        script,
        output,
        instructionsAnnotated: String(analysis.insights.instructions),
        syscalls: analysis.insights.syscalls.map(String),
        recommendations: ['Load the script in IDA Pro for detailed analysis.', 'Run `deep-dive` to complement with instruction analysis.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `IDA script export failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Visualize graph
app.post('/visualize-graph/:address', validateAddressMiddleware, async (req, res) => {
  const address = req.params.address;
  const { output = 'graph.dot' } = req.body;
  try {
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN' } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });

    const dotContent = `digraph { ${callGraph.edges.map(e => `"${String(e.from)}" -> "${String(e.to)}" [label="${String(e.action || 'unknown')}"]`).join(';')} }`;

    res.json({
      status: 'success',
      data: {
        graph: dotContent,
        output,
        nodes: String(callGraph.nodes.length),
        edges: String(callGraph.edges.length),
        recommendations: ['View graph using Graphviz or compatible tools.', 'Run `trace-interactions` to analyze key accounts.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Call graph visualization failed: ${err.message}`,
      debug: err.stack,
      support: 'support@solproof.org',
    });
  }
});

// Start server
const server = app.listen(PORT, () => {
  console.log(chalk.cyan(`SolProof SDK Server running on http://localhost:${PORT}`));
});

// Handle WebSocket upgrades for /monitor
server.on('upgrade', (request, socket, head) => {
  if (request.url.startsWith('/monitor')) {
    wss.handleUpgrade(request, socket, head, ws => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

// Initialize SOL price
fetchSolPrice();
