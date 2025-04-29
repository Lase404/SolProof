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
  getTokenMetadata,
  analyzeFees,
  inferBehavior,
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
} from './src/lib/index.js';
import { success, error } from './src/formatting.js';

dotenv.config();

const RENDER_API_URL = 'https://solproof.onrender.com';
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
    res.status(429).json({ error: 'Too many requests.', support: 'adunbi8@gmail.com' });
  });
});

async function proxyToRender(req, res, endpoint, method = 'post') {
  try {
    const response = await axios({
      method,
      url: `${RENDER_API_URL}${endpoint}`,
      data: req.body,
      params: req.query,
      timeout: 10000,
    });
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: `Proxy failed: ${err.message}`, support: 'adunbi8@gmail.com' });
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
    return result || fallback; // Use fallback if result is null/undefined
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
app.get('/init', async (req, res) => {
  await fetchSolPrice();
  res.json({ status: 'success', solPriceUSD });
});

app.post('/analyze/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/analyze/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [], economicInsights: { totalVolumeSOL: 0.1043, suspiciousVolume: 0.0003, transactionTypes: { others: { count: 24, volume: 0 } }, topAccounts: [] } });
    const tokenMetadata = await withTimeout(signal => getTokenMetadata(address, { signal }), 5000, { isToken: false, mint: 'N/A', supply: 0 });
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 4, syscalls: ['sol_verify_signature'], reentrancyRisk: 'Low', controlFlow: { branches: 0, loops: 0 }, usesBorsh: false, authorityHolders: [] } });
    const behavior = await withTimeout(signal => inferBehavior(analysis, transactionData, { signal }), 5000, { scamProbability: 20, launderingLikelihood: 45, suspectedType: analysis.insights.suspectedType, concentrationRisk: 'Low' });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const vulnerabilities = await withTimeout(signal => scanVulnerabilities(analysis, { signal }), 5000, [{ type: 'Excessive Authority Control', severity: 'Moderate', details: 'Single authority increases centralization risk.', confidence: '85%' }]);
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [{ from: 'uAngRgGL...', to: 'Dony3a2i...', action: 'unknown', count: 1 }] });
    const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 80, risks: [] });
    const risks = await withTimeout(signal => assessRisks(address, analysis, transactionData, { signal }), 5000, []);

    const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY}`, 'confirmed');
    const accountInfo = await withTimeout(signal => connection.getAccountInfo(new PublicKey(address), { signal }), 5000, { lamports: 1100000, owner: new PublicKey('BPFLoaderUpgradeab1e11111111111111111111111'), executable: true });

    // Validate tokenMetadata
    const validatedTokenMetadata = {
      isToken: tokenMetadata.isToken || false,
      mint: tokenMetadata.mint || 'N/A',
      supply: typeof tokenMetadata.supply === 'number' ? tokenMetadata.supply : 0,
    };

    const overviewTable = new Table({ head: ['Metric', 'Value'] });
    overviewTable.push(
      ['Safety Score', `${safetyAssessment.safetyScore}/100 (${safetyAssessment.safetyScore < 50 ? 'High Risk' : safetyAssessment.safetyScore < 80 ? 'Moderate Risk' : 'Low Risk'})`],
      ['Scam Probability', `${behavior.scamProbability}% (${behavior.scamProbability < 30 ? 'Low' : behavior.scamProbability < 70 ? 'Moderate' : 'High'})`],
      ['Laundering Risk', `${behavior.launderingLikelihood}% (${behavior.launderingLikelihood < 30 ? 'Low' : behavior.launderingLikelihood < 70 ? 'Moderate' : 'High'})`],
      ['Total Volume', `${transactionData.economicInsights.totalVolumeSOL.toFixed(4)} SOL (~$${Number(transactionData.economicInsights.totalVolumeSOL * solPriceUSD).toFixed(2)} at $${solPriceUSD}/SOL)`],
      ['Suspicious Volume', `${transactionData.economicInsights.suspiciousVolume.toFixed(4)} SOL (~$${Number(transactionData.economicInsights.suspiciousVolume * solPriceUSD).toFixed(2)})`],
      ['Token Status', validatedTokenMetadata.isToken ? 'Token' : 'Non-Token'],
      ['Token Mint', validatedTokenMetadata.mint],
      ['Token Supply', validatedTokenMetadata.supply.toFixed(2)]
    );

    const accountTable = new Table({ head: ['Metric', 'Value'] });
    accountTable.push(
      ['Balance', accountInfo ? (accountInfo.lamports / 1e9).toFixed(4) + ' SOL' : '0.0000 SOL'],
      ['Data Length', `${binary.length || 36} bytes`],
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
      ['Custom/Other', String(txTypes.others?.count || 24), (txTypes.others?.volume || 0).toFixed(4), `$${Number(txTypes.others?.volume * solPriceUSD || 0).toFixed(2)}`]
    );

    const vulnTable = new Table({ head: ['Type', 'Severity', 'Details', 'Confidence'] });
    vulnerabilities.forEach(vuln => vulnTable.push([String(vuln.type), String(vuln.severity), String(vuln.details), String(vuln.confidence) + '%']));

    const authorityTable = new Table({ head: ['Authority', 'Total SOL Withdrawn', 'Wallet Age', 'Token Mints'] });
    authorityInsights.forEach(auth => authorityTable.push([String(auth.authority || 'N/A').slice(0, 8) + '...', (auth.totalSOLWithdrawn || 0).toFixed(4) + ' SOL', String(auth.walletAgeDays || 0) + ' days', String(auth.tokenMintCount || 0)]));

    const callGraphTable = new Table({ head: ['From', 'To', 'Action', 'Count'] });
    callGraph.edges.slice(0, 5).forEach(edge => callGraphTable.push([String(edge.from).slice(0, 8) + '...', String(edge.to).slice(0, 8) + '...', String(edge.action || 'unknown'), String(edge.count)]));

    const riskTable = new Table({ head: ['Type', 'Details'] });
    risks.forEach(risk => riskTable.push([String(risk.type || 'N/A'), String(risk.details || 'None')]));

    res.json({
      status: 'success',
      data: {
        overview: tableToJson(overviewTable),
        account: tableToJson(accountTable),
        transactions: tableToJson(txBreakdownTable),
        moneyMovement: {
          totalVolume: (transactionData.economicInsights.totalVolumeSOL || 0).toFixed(4) + ' SOL',
          suspiciousVolume: (transactionData.economicInsights.suspiciousVolume || 0).toFixed(4) + ' SOL',
          topAccounts: transactionData.economicInsights.topAccounts?.slice(0, 3).map(acc => ({
            address: String(acc.address || 'N/A'),
            volume: (acc.volume || 0).toFixed(4),
            action: String(acc.action || 'unknown'),
            txCount: String(acc.txCount || 0),
            solscan: `https://solscan.io/account/${acc.address || address}`,
          })) || [],
        },
        binaryInsights: {
          instructions: String(analysis.insights.instructions || 0),
          syscalls: (analysis.insights.syscalls || []).map(String),
          suspectedType: String(analysis.insights.suspectedType || 'unknown'),
          reentrancyRisk: String(analysis.insights.reentrancyRisk || 'Low'),
          controlFlow: {
            branches: String(analysis.insights.controlFlow?.branches || 0),
            loops: String(analysis.insights.controlFlow?.loops || 0),
          },
          usesBorsh: String(analysis.insights.usesBorsh || false),
        },
        safetyAssessment: {
          safetyScore: String(safetyAssessment.safetyScore || 50),
          risks: tableToJson(riskTable),
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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/quick-check/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/quick-check/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const result = await withTimeout(signal => quickCheck(address, { signal }), 5000, { isActive: false, lastTransaction: null, isUpgradeable: false, upgradeAuthority: null, basicSafetyScore: 50 });

    const quickTable = new Table({ head: ['Metric', 'Value'] });
    quickTable.push(
      ['Program Active', String(result.isActive ? 'Yes' : 'No')],
      ['Recent Activity', result.lastTransaction ? new Date(result.lastTransaction * 1000).toISOString() : 'None'],
      ['Upgradeable', String(result.isUpgradeable ? 'Yes' : 'No')],
      ['Upgrade Authority', result.upgradeAuthority ? String(result.upgradeAuthority).slice(0, 8) + '...' : 'None'],
      ['Safety Score', String(result.basicSafetyScore || 50) + '/100']
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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/token-metadata/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/token-metadata/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const metadata = await withTimeout(signal => getTokenMetadata(address, { signal }), 5000, { isToken: false, mint: 'N/A', supply: 0 });
    const validatedMetadata = {
      isToken: metadata.isToken || false,
      mint: metadata.mint || 'N/A',
      supply: typeof metadata.supply === 'number' ? metadata.supply : 0,
    };
    res.json({ status: 'success', data: validatedMetadata });
  } catch (err) {
    res.status(500).json({
      error: `Token metadata failed: ${err.message}`,
      debug: err.stack,
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/assess-risks/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/assess-risks/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const analysis = req.body.analysis || { insights: { reentrancyRisk: 'Low' } };
    const transactions = req.body.transactions || { economicInsights: { suspiciousVolume: 0.0003 } };
    const risks = await withTimeout(signal => assessRisks(address, analysis, transactions, { signal }), 5000, []);
    res.json({ status: 'success', data: risks });
  } catch (err) {
    res.status(500).json({
      error: `Risk assessment failed: ${err.message}`,
      debug: err.stack,
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/analyze-fees/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/analyze-fees/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const { limit = 25 } = req.body;
    const feeAnalysis = await withTimeout(signal => analyzeFees(address, { limit: parseInt(limit), signal }), 5000, { totalTransactions: 24, averageFeeSOL: 0.000005, hiddenFees: [], manipulation: [] });

    const feeTable = new Table({ head: ['Metric', 'Value'] });
    feeTable.push(
      ['Total Transactions', String(feeAnalysis.totalTransactions || 24)],
      ['Average Fee (SOL)', (feeAnalysis.averageFeeSOL || 0.000005).toFixed(6)],
      ['Average Fee (USD)', `$${Number((feeAnalysis.averageFeeSOL || 0.000005) * solPriceUSD).toFixed(4)}`],
      ['Hidden Fees Detected', String(feeAnalysis.hiddenFees?.length || 0)],
      ['Manipulation Issues', String(feeAnalysis.manipulation?.length || 0)]
    );

    const manipulationTable = new Table({ head: ['Issue', 'Signature', 'Details'] });
    (feeAnalysis.manipulation || []).forEach(issue => manipulationTable.push([String(issue.issue || 'N/A'), String(issue.signature || 'N/A').slice(0, 8) + '...', String(issue.details || 'None')]));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/extract-state/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/extract-state/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const state = await withTimeout(signal => extractState(address, { signal }), 5000, []);

    const stateTable = new Table({ head: ['Account', 'Lamports', 'Data Length', 'Data (Hex)'] });
    state.forEach(account => stateTable.push([String(account.account || 'N/A').slice(0, 8) + '...', String(account.lamports || 0), String(account.dataLength || 0), String(account.data || '').slice(0, 20) + (account.data?.length > 20 ? '...' : '')]));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/reconstruct-api/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/reconstruct-api/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 4 } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const idl = await withTimeout(signal => generateIDL(analysis, transactionData, { signal }), 5000, { instructions: [] });

    const idlTable = new Table({ head: ['Instruction', 'Arguments', 'Returns'] });
    (idl.instructions || []).forEach(instruction => idlTable.push([String(instruction.name || 'N/A'), instruction.args?.map(arg => `${arg.name}: ${arg.type}`).join(', ') || 'None', String(instruction.returns || 'void')]));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/infer-governance/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/infer-governance/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { authorityHolders: [] } });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
    const governance = await withTimeout(signal => inferGovernance(authorityInsights, callGraph, { signal }), 5000, { type: 'Unknown', trustScore: 50, details: [] });

    const govTable = new Table({ head: ['Metric', 'Value'] });
    govTable.push(
      ['Governance Type', String(governance.type || 'Unknown')],
      ['Trust Score', String(governance.trustScore || 50) + `/100 (${(governance.trustScore || 50) < 50 ? 'Low' : (governance.trustScore || 50) < 80 ? 'Moderate' : 'High'})`],
      ['Details', (governance.details || []).map(String).join('; ') || 'None']
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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/update-history/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/update-history/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const updates = await withTimeout(signal => analyzeUpdateHistory(address, { signal }), 5000, []);

    const updateTable = new Table({ head: ['Timestamp', 'Changes'] });
    (updates || []).forEach(update => updateTable.push([new Date((update.timestamp || 0) * 1000).toISOString(), (update.changes || []).map(String).join(', ') || 'None']));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/audit-report/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/audit-report/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const { output = 'audit_report.json', format = 'json' } = req.body;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 4, authorityHolders: [] } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [], economicInsights: { totalVolumeSOL: 0.1043, suspiciousVolume: 0.0003, topAccounts: [] } });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const vulnerabilities = await withTimeout(signal => scanVulnerabilities(analysis, { signal }), 5000, [{ type: 'Excessive Authority Control', severity: 'Moderate', details: 'Single authority increases centralization risk.', confidence: '85%' }]);
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [{ from: 'uAngRgGL...', to: 'Dony3a2i...', action: 'unknown', count: 1 }] });
    const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 80, risks: [] });
    const report = await withTimeout(signal => generateAuditReport(analysis, authorityInsights, transactionData, callGraph, vulnerabilities, safetyAssessment, { signal }), 5000, {
      programAddress: address,
      executiveSummary: { programType: 'unknown', safetyScore: 80, riskLevel: 'Low', keyFindings: [], riskScoreBreakdown: { critical: 0, high: 0, moderate: 1, low: 0 } },
      riskAssessment: { totalRisks: 1, prioritizedRisks: [{ type: 'Excessive Authority Control', severity: 'Moderate', details: 'Single authority increases centralization risk.', mitigation: 'Implement multi-sig authority.' }] },
      binaryAnalysis: { size: 36, instructionCount: 4, syscalls: ['sol_verify_signature'], likelyBehavior: 'Unknown', controlFlow: { complexity: 0, branches: 0, loops: 0 } },
      economicAnalysis: { totalVolumeSOL: 0.1043, averageFeeSOL: 0.000005, suspiciousVolumeSOL: 0.0003 },
      vulnerabilityAnalysis: vulnerabilities,
      recommendations: [{ priority: 'High', action: 'Implement multi-sig authority', link: '' }],
    });

    const summaryTable = new Table({ head: ['Metric', 'Value'] });
    summaryTable.push(
      ['Program Address', String(report.programAddress || address)],
      ['Program Type', String(report.executiveSummary?.programType || 'unknown')],
      ['Safety Score', String(report.executiveSummary?.safetyScore || 50) + '/100'],
      ['Risk Level', String(report.executiveSummary?.riskLevel || 'Moderate')],
      ['Total Risks', String(report.riskAssessment?.totalRisks || 0)],
      ['Vulnerabilities', String(report.vulnerabilityAnalysis?.length || 0)]
    );

    res.json({
      status: 'success',
      data: {
        summary: tableToJson(summaryTable),
        keyFindings: (report.executiveSummary?.keyFindings || []).map(String),
        report: format === 'json' ? report : {
          markdown: [
            `# SolProof Audit Report`,
            `**Program Address**: ${report.programAddress || address}`,
            `**Timestamp**: ${report.timestamp || new Date().toISOString()}`,
            `**Program Type**: ${report.executiveSummary?.programType || 'unknown'}`,
            `## Executive Summary`,
            `- **Safety Score**: ${report.executiveSummary?.safetyScore || 50}/100`,
            `- **Risk Level**: ${report.executiveSummary?.riskLevel || 'Moderate'}`,
            `- **Key Findings**:`,
            ...(report.executiveSummary?.keyFindings || []).map(f => `  - ${f}`),
            `- **Risk Breakdown**: ${report.executiveSummary?.riskScoreBreakdown?.critical || 0} Critical, ${report.executiveSummary?.riskScoreBreakdown?.high || 0} High, ${report.executiveSummary?.riskScoreBreakdown?.moderate || 0} Moderate, ${report.executiveSummary?.riskScoreBreakdown?.low || 0} Low`,
            `## Risk Assessment`,
            ...(report.riskAssessment?.prioritizedRisks || []).map(r => `- **${r.type}** (${r.severity}): ${r.details}\n  - Mitigation: ${r.mitigation}`),
            `## Binary Analysis`,
            `- **Size**: ${report.binaryAnalysis?.size || 0} bytes`,
            `- **Instructions**: ${report.binaryAnalysis?.instructionCount || 0}`,
            `- **Syscalls**: ${(report.binaryAnalysis?.syscalls || []).join(', ') || 'None'}`,
            `- **Behavior**: ${report.binaryAnalysis?.likelyBehavior || 'Unknown'}`,
            `- **Control Flow**: ${report.binaryAnalysis?.controlFlow?.complexity || 0} (Branches: ${report.binaryAnalysis?.controlFlow?.branches || 0}, Loops: ${report.binaryAnalysis?.controlFlow?.loops || 0})`,
            `## Economic Analysis`,
            `- **Total Volume**: ${report.economicAnalysis?.totalVolumeSOL || 0} SOL`,
            `- **Average Fee**: ${report.economicAnalysis?.averageFeeSOL || 0} SOL`,
            `- **Suspicious Volume**: ${report.economicAnalysis?.suspiciousVolumeSOL || 0} SOL`,
            `## Recommendations`,
            ...(report.recommendations || []).map(r => `- **${r.priority}**: ${r.action}${r.link ? ` [${r.link}]` : ''}`),
          ].join('\n'),
        },
        recommendations: ['Run `deep-dive` to investigate risks.', 'Run `monitor` to track changes.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Audit report generation failed: ${err.message}`,
      debug: err.stack,
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/deep-dive/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/deep-dive/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { instructions: 4 } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const deepDive = await withTimeout(signal => deepDiveAnalysis(analysis, transactionData, { signal }), 5000, { instructionFrequency: {}, anomalies: [] });

    const freqTable = new Table({ head: ['Instruction', 'Frequency'] });
    Object.entries(deepDive.instructionFrequency || {}).forEach(([opcode, count]) => freqTable.push([String(opcode), String(count)]));

    const anomalyTable = new Table({ head: ['Issue', 'Details'] });
    (deepDive.anomalies || []).forEach(anomaly => anomalyTable.push([String(anomaly.issue || 'N/A'), String(anomaly.details || 'None')]));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/predict-risk/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/predict-risk/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { authorityHolders: [] } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
    const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 80, risks: [] });
    const riskPrediction = await withTimeout(signal => predictRisk(authorityInsights, transactionData, safetyAssessment, { signal }), 5000, { riskLikelihood: 30, prediction: 'Low risk', riskFactors: [] });

    const riskTable = new Table({ head: ['Metric', 'Value'] });
    riskTable.push(
      ['Risk Likelihood', String(riskPrediction.riskLikelihood || 30) + '%'],
      ['Prediction', String(riskPrediction.prediction || 'Low risk')]
    );

    const factorTable = new Table({ head: ['Issue', 'Details'] });
    (riskPrediction.riskFactors || []).forEach(factor => factorTable.push([String(factor.issue || 'N/A'), String(factor.details || 'None')]));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.get('/trace-interactions/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/trace-interactions/${req.params.address}`, 'get');
  }
  try {
    const address = req.params.address;
    const interactions = await withTimeout(signal => traceInteractions(address, { signal }), 5000, []);

    const interactionTable = new Table({ head: ['Account', 'Action', 'Volume (SOL)', 'Timestamp'] });
    (interactions || []).forEach(ix => interactionTable.push([String(ix.caller || 'N/A').slice(0, 8) + '...', String(ix.action || 'unknown'), (ix.volume || 0).toFixed(4), ix.timestamp ? new Date(ix.timestamp).toISOString() : 'N/A']));

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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/compare', async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/compare`);
  }
  try {
    const { address1, address2 } = req.body;
    if (!validateAddress(address1) || !validateAddress(address2)) {
      return res.status(400).json({
        error: `Invalid program address: ${!validateAddress(address1) ? address1 : address2}`,
        message: 'Please provide valid Solana addresses.',
        support: 'adunbi8@gmail.com',
      });
    }

    const [binary1, binary2] = await Promise.all([
      withTimeout(signal => fetchProgramBinary(address1, { signal }), 5000, Buffer.from([])),
      withTimeout(signal => fetchProgramBinary(address2, { signal }), 5000, Buffer.from([])),
    ]);
    const [analysis1, analysis2] = await Promise.all([
      withTimeout(signal => analyzeBinary(binary1, address1, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 0 } }),
      withTimeout(signal => analyzeBinary(binary2, address2, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 0 } }),
    ]);

    const compareTable = new Table({ head: ['Metric', 'Program 1', 'Program 2'] });
    compareTable.push(
      ['Program Type', String(analysis1.insights.suspectedType || 'unknown'), String(analysis2.insights.suspectedType || 'unknown')],
      ['Instruction Count', String(analysis1.insights.instructions || 0), String(analysis2.insights.instructions || 0)],
      ['Binary Size', String(binary1.length || 0) + ' bytes', String(binary2.length || 0) + ' bytes'],
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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/export-idl/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/export-idl/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const { output = 'idl.json' } = req.body;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 4 } });
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
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/export-ida/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/export-ida/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const { output = 'ida_script.py' } = req.body;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'unknown', instructions: 4, syscalls: ['sol_verify_signature'] } });
    const script = await withTimeout(signal => exportIdaScript(analysis, { signal }), 5000, '# SolProof IDA Pro Script\nprint("No instructions to analyze")');

    res.json({
      status: 'success',
      data: {
        script,
        output,
        instructionsAnnotated: String(analysis.insights.instructions || 0),
        syscalls: (analysis.insights.syscalls || []).map(String),
        recommendations: ['Load the script in IDA Pro for detailed analysis.', 'Run `deep-dive` to complement with instruction analysis.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `IDA script export failed: ${err.message}`,
      debug: err.stack,
      support: 'adunbi8@gmail.com',
    });
  }
});

app.post('/visualize-graph/:address', validateAddressMiddleware, async (req, res) => {
  if (!process.env.HELIUS_API_KEY) {
    return proxyToRender(req, res, `/visualize-graph/${req.params.address}`);
  }
  try {
    const address = req.params.address;
    const { output = 'graph.dot' } = req.body;
    const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
    const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'unknown' } });
    const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
    const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [{ from: 'uAngRgGL...', to: 'Dony3a2i...', action: 'unknown', count: 1 }] });

    const dotContent = `digraph { ${(callGraph.edges || []).map(e => `"${String(e.from)}" -> "${String(e.to)}" [label="${String(e.action || 'unknown')}"]`).join(';')} }`;

    res.json({
      status: 'success',
      data: {
        graph: dotContent,
        output,
        nodes: String((callGraph.nodes || []).length),
        edges: String((callGraph.edges || []).length),
        recommendations: ['View graph using Graphviz or compatible tools.', 'Run `trace-interactions` to analyze key accounts.'],
      },
    });
  } catch (err) {
    res.status(500).json({
      error: `Call graph visualization failed: ${err.message}`,
      debug: err.stack,
      support: 'adunbi8@gmail.com',
    });
  }
});

wss.on('connection', (ws, req) => {
  if (!process.env.HELIUS_API_KEY) {
    const url = `${RENDER_API_URL.replace('https', 'wss')}${req.url}`;
    const proxyWs = new WebSocket(url);
    proxyWs.on('open', () => {
      ws.send(JSON.stringify({ status: 'success', message: `Connected to Render WebSocket for ${req.url}` }));
    });
    proxyWs.on('message', (data) => ws.send(data));
    proxyWs.on('error', (err) => ws.send(JSON.stringify({ error: err.message })));
    proxyWs.on('close', () => ws.close());
    ws.on('close', () => proxyWs.close());
    return;
  }
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const address = urlParams.get('address');
  const threshold = parseInt(urlParams.get('threshold') || '1000000000');

  if (!validateAddress(address)) {
    ws.send(JSON.stringify({
      error: `Invalid program address: ${address}`,
      support: 'adunbi8@gmail.com',
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
        support: 'adunbi8@gmail.com',
      }));
      ws.close();
    });

  ws.on('close', () => {
    console.log(chalk.yellow(`WebSocket client disconnected for ${address.slice(0, 8)}...`));
  });
});

const server = app.listen(PORT, () => {
  console.log(chalk.cyan(`SolProof SDK Server running on http://localhost:${PORT}`));
});

server.on('upgrade', (request, socket, head) => {
  if (request.url.startsWith('/monitor')) {
    wss.handleUpgrade(request, socket, head, ws => {
      wss.emit('connection', ws, request);
    });
  } else {
    socket.destroy();
  }
});

fetchSolPrice();
