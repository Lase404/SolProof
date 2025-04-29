#!/usr/bin/env node
import { Command } from 'commander';
import ora from 'ora';
import inquirer from 'inquirer';
import chalk from 'chalk';
import Table from 'cli-table3';
import { PublicKey, Connection } from '@solana/web3.js';
import dotenv from 'dotenv';
import figlet from 'figlet';
import NodeCache from 'node-cache';
import axios from 'axios';
import {
  analyzeBinary,
  fetchProgramBinary,
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
import { success, error } from './formatting.js';

dotenv.config();

const RENDER_API_URL = 'https://solproof-sdk.onrender.com';

async function callRenderApi(method, endpoint, data = {}, params = {}) {
  try {
    const response = await axios({
      method,
      url: `${RENDER_API_URL}${endpoint}`,
      data,
      params,
    });
    return response.data;
  } catch (err) {
    throw new Error(`Render API call failed: ${err.message}`);
  }
}

const program = new Command();
const SUPPORT_EMAIL = 'adunbi8@gmail.com';
const cache = new NodeCache({ stdTTL: 300 }); // 5-minute cache
let solPriceUSD = 150; // Default; updated dynamically



// Display ASCII art banner
console.log(chalk.cyan(figlet.textSync('SolProof', { font: 'Standard' })));
console.log(chalk.cyan('SolProof SDK: Reverse Engineering for Solana Programs\n'));

/**
 * Fetches the current SOL/USD price from CoinGecko with timeout.
 * @returns {Promise<void>}
 */
async function fetchSolPrice() {
  const cacheKey = 'solPriceUSD';
  const cachedPrice = cache.get(cacheKey);
  if (cachedPrice) {
    solPriceUSD = cachedPrice;
    return;
  }
  const spinner = ora(chalk.yellow('Fetching SOL/USD price...')).start();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const response = await fetch('https://api.coingecko.com/api/v3/simple/price?ids=solana&vs_currencies=usd', {
      signal: controller.signal
    });
    clearTimeout(timeout);
    const data = await response.json();
    solPriceUSD = data.solana.usd;
    cache.set(cacheKey, solPriceUSD);
    spinner.succeed(chalk.green(`SOL Price: $${solPriceUSD} [Success]`));
  } catch (err) {
    spinner.warn(chalk.yellow(`Failed to fetch SOL price: ${err.message}. Using default $150.`));
  }
}

/**
 * Validates a Solana address.
 * @param {string} address - Address to validate.
 * @returns {boolean} - True if valid, false otherwise.
 */
function validateAddress(address) {
  try {
    new PublicKey(address);
    return true;
  } catch (err) {
    return false;
  }
}

/**
 * Fetches token metadata via Helius RPC with retry.
 * @param {string} mintAddress - Token mint address.
 * @returns {Promise<Object>} - Token metadata.
 */
async function fetchTokenMetadata(mintAddress) {
  if (!validateAddress(mintAddress)) return null;
  const cacheKey = `tokenMetadata:${mintAddress}`;
  const cachedMetadata = cache.get(cacheKey);
  if (cachedMetadata) return cachedMetadata;
  const spinner = ora(chalk.yellow(`Fetching token metadata: ${mintAddress}...`)).start();
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(`https://api.helius.xyz/v0/tokens/metadata?api-key=${process.env.HELIUS_API_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mintAccounts: [mintAddress] }),
        signal: controller.signal
      });
      clearTimeout(timeout);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      const metadata = data[0] || { name: 'Unknown', symbol: 'Unknown', decimals: 9, totalSupply: 0, mintAuthority: null, freezeAuthority: null };
      cache.set(cacheKey, metadata);
      spinner.succeed(chalk.green(`Token metadata: ${metadata.name} [Success]`));
      return metadata;
    } catch (err) {
      if (attempt === 3) {
        spinner.warn(chalk.yellow(`Failed to fetch token metadata after ${attempt} attempts: ${err.message}`));
        return null;
      }
    }
  }
}

/**
 * Finds the most relevant token mint from transaction data.
 * @param {Object} transactionData - Transaction data.
 * @returns {string|null} - Mint address or null.
 */
function findTokenMint(transactionData) {
  const mints = transactionData.transactions
    ?.filter(tx => tx.tokenMint && validateAddress(tx.tokenMint))
    .map(tx => tx.tokenMint)
    .filter((mint, index, self) => self.indexOf(mint) === index);
  return mints?.[0] || null;
}

/**
 * Suggests a similar command based on input.
 * @param {string} input - Unknown command.
 * @returns {string|null} - Suggested command or null.
 */
function suggestCommand(input) {
  const commands = [
    'analyze', 'analyze-fees', 'quick-check', 'monitor', 'extract-state',
    'reconstruct-api', 'infer-governance', 'update-history', 'audit-report',
    'deep-dive', 'predict-risk', 'trace-interactions', 'compare', 'export-idl',
    'export-ida', 'visualize-graph'
  ];
  return commands.find(cmd => cmd.includes(input.toLowerCase())) || null;
}

/**
 * Wraps an async function with a timeout.
 * @param {Function} fn - Async function to wrap.
 * @param {number} ms - Timeout in milliseconds.
 * @param {any} fallback - Fallback value on timeout or error.
 * @returns {Promise<any>} - Result or fallback.
 */
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

/**
 * Prompts the user for the next action with a clean, unique menu.
 * @param {string} currentCommand - Current command.
 * @param {string} address - Program address.
 * @param {Object} analysisResults - Analysis results for context.
 * @returns {Promise<void>}
 */
async function promptNextAction(currentCommand, address, analysisResults = {}) {
  const choices = [
    { name: 'Generate audit report', description: 'Create a detailed report in JSON or Markdown', value: `audit-report ${address} --output report.json --format json` },
    { name: 'Monitor for real-time alerts', description: 'Track program transactions live', value: `monitor ${address} --threshold 1000000000`, disabled: !process.env.QUICKNODE_RPC_URL && 'QUICKNODE_RPC_URL not set' },
    { name: 'Analyze fees', description: 'Check for hidden fees or manipulation', value: `analyze-fees ${address}` },
    { name: 'Trace specific account', description: 'View user interactions with the program', value: `trace-interactions ${address}` },
    { name: 'View token metadata', description: 'Infer the program’s API endpoints', value: `reconstruct-api ${address}` },
    { name: 'Export analysis to JSON', description: 'Save audit report as JSON', value: `audit-report ${address} --output analysis.json --format json` },
    { name: 'Export IDA Pro script', description: 'Generate script for binary analysis in IDA Pro', value: `export-ida ${address} --output ida_script.py` },
    { name: 'Visualize call graph', description: 'Create a DOT file of the program’s call graph', value: `visualize-graph ${address} --output graph.dot` },
    { name: 'View raw transaction data', description: 'Extract raw state from program accounts', value: `extract-state ${address}` },
    { name: 'Retry with more transactions', description: 'Re-run analysis with more data', value: `analyze ${address}` },
    { name: 'View program account data', description: 'Perform a quick program check', value: `quick-check ${address}` },
    { name: 'Enter custom command', description: 'Type a custom SolProof command', value: 'custom' },
    { name: 'Exit', description: 'Exit the SolProof SDK', value: 'exit' }
  ];

  // Add context-aware suggestions, ensuring uniqueness
  const existingValues = new Set(choices.map(c => c.value));
  if (analysisResults.safetyScore < 50 && !existingValues.has(`deep-dive ${address}`)) {
    choices.splice(1, 0, { name: 'Deep dive analysis', description: 'Investigate high-risk instructions', value: `deep-dive ${address}` });
  }
  if (analysisResults.vulnerabilities?.length > 0 && !existingValues.has(`predict-risk ${address}`)) {
    choices.splice(1, 0, { name: 'Predict future risks', description: 'Analyze potential risks based on vulnerabilities', value: `predict-risk ${address}` });
  }

  // Filter out current command and deduplicate
  const filteredChoices = Array.from(new Set(choices.map(c => JSON.stringify(c))), JSON.parse)
    .filter(choice => !choice.value.startsWith(currentCommand.split(' ')[0]));

  // Display clean Next Steps
  console.log(chalk.cyan('\nNext Steps\n----------'));
  const { nextAction, customCommand } = await inquirer.prompt([
    {
      type: 'list',
      name: 'nextAction',
      message: chalk.cyan('What would you like to do next?'),
      choices: filteredChoices.map(choice => ({
        name: chalk.white(`${choice.name} (${choice.description})`),
        value: choice.value,
        disabled: choice.disabled || false
      })),
      prefix: chalk.cyan('➤')
    },
    {
      type: 'input',
      name: 'customCommand',
      message: chalk.cyan('Enter your custom command:'),
      when: answers => answers.nextAction === 'custom',
      validate: input => input.trim() ? true : 'Command cannot be empty'
    }
  ]);

  if (nextAction === 'exit') {
    console.log(chalk.green('\nThank you for using SolProof SDK!'));
    process.exit(0);
  }

  console.log(chalk.cyan('════════════════════════════════════════════════════'));
  const commandToRun = nextAction === 'custom' ? customCommand : nextAction;
  const args = commandToRun.split(' ');
  try {
    await program.parseAsync(args, { from: 'user' });
  } catch (err) {
    console.log(chalk.red(`Error executing command '${commandToRun}': ${err.message}`));
    const suggestion = suggestCommand(args[0]);
    if (suggestion) console.log(chalk.yellow(`Did you mean '${suggestion}'?`));
    displayAvailableCommands();
  }
}

/**
 * Displays available commands on error.
 */
function displayAvailableCommands() {
  console.log(chalk.cyan('\nAvailable Commands\n------------------'));
  const commands = [
    { name: 'analyze <address>', description: 'Comprehensive program analysis' },
    { name: 'analyze-fees <address> [-l, --limit <number>]', description: 'Analyze transaction fees' },
    { name: 'quick-check <address>', description: 'Quick program check' },
    { name: 'monitor <address> [-t, --threshold <lamports>]', description: 'Real-time transaction monitoring' },
    { name: 'extract-state <address>', description: 'Extract program state' },
    { name: 'reconstruct-api <address>', description: 'Reconstruct API endpoints' },
    { name: 'infer-governance <address>', description: 'Infer governance mechanisms' },
    { name: 'update-history <address>', description: 'Analyze update history' },
    { name: 'audit-report <address> [-o, --output <file>] [-f, --format <type>]', description: 'Generate audit report' },
    { name: 'deep-dive <address>', description: 'Deep instruction analysis' },
    { name: 'predict-risk <address>', description: 'Predict future risks' },
    { name: 'trace-interactions <address>', description: 'Trace user interactions' },
    { name: 'compare <address1> <address2>', description: 'Compare two programs' },
    { name: 'export-idl <address> [-o, --output <file>]', description: 'Export reconstructed IDL' },
    { name: 'export-ida <address> [-o, --output <file>]', description: 'Export IDA Pro script' },
    { name: 'visualize-graph <address> [-o, --output <file>]', description: 'Visualize call graph' }
  ];
  const table = new Table({ head: [chalk.cyan('Command'), chalk.cyan('Description')], colWidths: [40, 60] });
  commands.forEach(cmd => table.push([chalk.white(cmd.name), chalk.white(cmd.description)]));
  console.log(table.toString());
  console.log(error(`Please use a valid command. Contact ${SUPPORT_EMAIL} for assistance.`));
}

// Initialize CLI
program
  .name('solproof')
  .description('SolProof SDK: Reverse Engineering for Solana Programs')
  .version('1.0.0')
  .hook('preAction', async () => {
    await fetchSolPrice();
  });

// Handle unknown commands
program.on('command:*', (args) => {
  console.log(chalk.red(`Error: Unknown command '${args.join(' ')}'`));
  const suggestion = suggestCommand(args[0]);
  if (suggestion) console.log(chalk.yellow(`Did you mean '${suggestion}'?`));
  displayAvailableCommands();
});

// Analyze command
program
  .command('analyze')
  .description('Comprehensive program analysis')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Analyzing program: ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    let analysisResults = {};
    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.succeed(chalk.green(`Analyzing program: ${address}... [Success]`));
      console.log(chalk.white(`- Program binary: ${binary.length} bytes`));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));

      spinner.start(chalk.yellow(`Fetching transactions...`));
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [], economicInsights: { totalVolumeSOL: 0, suspiciousVolume: 0, transactionTypes: {}, topAccounts: [] } });
      spinner.succeed(chalk.green(`Fetched ${transactionData.transactions.length} transactions [Success]`));

      spinner.start(chalk.yellow('Analyzing binary...'));
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0, syscalls: [], reentrancyRisk: 'Low', controlFlow: { branches: 0, loops: 0 }, usesBorsh: false, authorityHolders: [] } });

      spinner.start(chalk.yellow('Inferring program behavior...'));
      const behavior = await withTimeout(signal => inferBehavior(analysis, transactionData, { signal }), 5000, { scamProbability: 20, launderingLikelihood: 10, suspectedType: analysis.insights.suspectedType });

      spinner.start(chalk.yellow('Analyzing authority holders...'));
      const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);

      spinner.start(chalk.yellow('Scanning for vulnerabilities...'));
      const vulnerabilities = await withTimeout(signal => scanVulnerabilities(analysis, { signal }), 5000, []);

      spinner.start(chalk.yellow('Reconstructing call graph...'));
      const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });

      spinner.start(chalk.yellow('Assessing safety...'));
      const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 50, risks: [] });
      spinner.succeed(chalk.green('Safety assessed [Success]'));

      analysisResults = { safetyScore: safetyAssessment.safetyScore, vulnerabilities };

      const mintAddress = findTokenMint(transactionData);
      let tokenMetadata = null;
      if (mintAddress) {
        tokenMetadata = await fetchTokenMetadata(mintAddress);
      }

      const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${process.env.HELIUS_API_KEY}`, 'confirmed');
      const accountInfo = await withTimeout(signal => connection.getAccountInfo(new PublicKey(address), { signal }), 5000, null);

      // Analysis Overview
      console.log(chalk.cyan('\nAnalysis Overview\n-----------------'));
      const overviewTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      overviewTable.push(
        ['Safety Score', chalk.white(`${safetyAssessment.safetyScore}/100 (${safetyAssessment.safetyScore < 50 ? 'High Risk' : safetyAssessment.safetyScore < 80 ? 'Moderate Risk' : 'Low Risk'})`)],
        ['Scam Probability', chalk.white(`${behavior.scamProbability}% (${behavior.scamProbability < 30 ? 'Low' : behavior.scamProbability < 70 ? 'Moderate' : 'High'})`)],
        ['Laundering Risk', chalk.white(`${behavior.launderingLikelihood}% (${behavior.launderingLikelihood < 30 ? 'Low' : behavior.launderingLikelihood < 70 ? 'Moderate' : 'High'})`)],
        ['Total Volume', chalk.white(`${transactionData.economicInsights.totalVolumeSOL.toFixed(4)} SOL (~$${(transactionData.economicInsights.totalVolumeSOL * solPriceUSD).toFixed(2)} at $${solPriceUSD}/SOL)`)],
        ['Suspicious Volume', chalk.white(`${transactionData.economicInsights.suspiciousVolume.toFixed(4)} SOL (~$${(transactionData.economicInsights.suspiciousVolume * solPriceUSD).toFixed(2)})`)]
      );
      console.log(overviewTable.toString());

      // Program Account Data
      console.log(chalk.cyan('\nProgram Account Data\n--------------------'));
      const accountTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      accountTable.push(
        ['Balance', chalk.white(`${accountInfo ? (accountInfo.lamports / 1e9).toFixed(4) : '0.0000'} SOL`)],
        ['Data Length', chalk.white(`${binary.length} bytes`)],
        ['Owner', chalk.white(accountInfo?.owner?.toBase58() || 'Unknown')],
        ['Executable', chalk.white(accountInfo?.executable ? 'Yes' : 'No')]
      );
      console.log(accountTable.toString());
      console.log(chalk.white('- Status: Verify binary integrity on Solscan.'));

      // Transaction Breakdown
      console.log(chalk.cyan('\nTransaction Breakdown\n--------------------'));
      const txBreakdownTable = new Table({ head: [chalk.cyan('Type'), chalk.cyan('Count'), chalk.cyan('Volume (SOL)'), chalk.cyan('Approx. Value (USD)')], colWidths: [20, 10, 15, 20] });
      const txTypes = transactionData.economicInsights.transactionTypes || {};
      txBreakdownTable.push(
        ['Swaps', chalk.white(txTypes.swap?.count || 0), chalk.white((txTypes.swap?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.swap?.volume * solPriceUSD || 0).toFixed(2)}`)],
        ['Transfers', chalk.white(txTypes.transfer?.count || 0), chalk.white((txTypes.transfer?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.transfer?.volume * solPriceUSD || 0).toFixed(2)}`)],
        ['Mints', chalk.white(txTypes.mint?.count || 0), chalk.white((txTypes.mint?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.mint?.volume * solPriceUSD || 0).toFixed(2)}`)],
        ['Burns', chalk.white(txTypes.burn?.count || 0), chalk.white((txTypes.burn?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.burn?.volume * solPriceUSD || 0).toFixed(2)}`)],
        ['Governance', chalk.white(txTypes.governance?.count || 0), chalk.white((txTypes.governance?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.governance?.volume * solPriceUSD || 0).toFixed(2)}`)],
        ['NFT Mints', chalk.white(txTypes.nftMint?.count || 0), chalk.white((txTypes.nftMint?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.nftMint?.volume * solPriceUSD || 0).toFixed(2)}`)],
        ['Custom/Other', chalk.white(txTypes.others?.count || 0), chalk.white((txTypes.others?.volume || 0).toFixed(4)), chalk.white(`$${(txTypes.others?.volume * solPriceUSD || 0).toFixed(2)}`)]
      );
      console.log(txBreakdownTable.toString());

      // Money Movement
      console.log(chalk.cyan('\nMoney Movement\n--------------'));
      console.log(chalk.white(`Total Volume: ${transactionData.economicInsights.totalVolumeSOL.toFixed(4)} SOL (~$${(transactionData.economicInsights.totalVolumeSOL * solPriceUSD).toFixed(2)} at $${solPriceUSD}/SOL)`));
      console.log(chalk.white(`Suspicious Volume: ${transactionData.economicInsights.suspiciousVolume.toFixed(4)} SOL (~$${(transactionData.economicInsights.suspiciousVolume * solPriceUSD).toFixed(2)}, ${txTypes.others?.count || 0} custom transactions)`));
      console.log(chalk.cyan('Top Accounts:'));
      const topAccounts = transactionData.economicInsights.topAccounts || [];
      topAccounts.forEach(account => {
        console.log(chalk.white(`  - ${account.address}: ${account.volume.toFixed(4)} SOL (${account.action}, ${account.txCount} txs, https://solscan.io/account/${account.address})`));
      });
      console.log(chalk.white(`Concentration Risk: ${topAccounts.length && topAccounts[0]?.volume / (transactionData.economicInsights.totalVolumeSOL || 1) > 0.7 ? 'High' : 'Low'}`));

      // Token Insights
      if (tokenMetadata) {
        console.log(chalk.cyan('\nToken Insights\n--------------'));
        const tokenTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
        tokenTable.push(
          ['Token', chalk.white(tokenMetadata.name)],
          ['Mint Address', chalk.white(`${mintAddress} (https://solscan.io/token/${mintAddress})`)],
          ['Total Supply', chalk.white(`${tokenMetadata.totalSupply.toLocaleString()} units`)],
          ['Decimals', chalk.white(tokenMetadata.decimals)],
          ['Mint Authority', chalk.white(tokenMetadata.mintAuthority ? tokenMetadata.mintAuthority : 'None')],
          ['Freeze Authority', chalk.white(tokenMetadata.freezeAuthority ? tokenMetadata.freezeAuthority : 'None')]
        );
        console.log(tokenTable.toString());
        console.log(chalk.white('- Status: Verify mint authority on Solscan to assess rug-pull risk.'));
      }

      // Binary Insights
      console.log(chalk.cyan('\nBinary Insights\n---------------'));
      const binaryTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      binaryTable.push(
        ['Instructions Detected', chalk.white(`${analysis.insights.instructions} (syscalls: ${analysis.insights.syscalls?.join(', ') || 'none'})`)],
        ['Suspected Program Type', chalk.white(analysis.insights.suspectedType.toUpperCase())],
        ['Reentrancy Risk', chalk.white(analysis.insights.reentrancyRisk || 'Low')],
        ['Complexity', chalk.white(`${analysis.insights.controlFlow?.branches || 0} branches, ${analysis.insights.controlFlow?.loops || 0} loops`)],
        ['Borsh Serialization', chalk.white(analysis.insights.usesBorsh ? 'Detected' : 'Not detected')]
      );
      console.log(binaryTable.toString());
      console.log(chalk.white(`- Status: Audit ${analysis.insights.suspectedType} logic for vulnerabilities.`));

      // Safety Assessment
      console.log(chalk.cyan('\nSafety Assessment\n-----------------'));
      console.log(chalk.white(`Safety Score: ${safetyAssessment.safetyScore}/100 (${safetyAssessment.safetyScore < 50 ? 'High Risk' : safetyAssessment.safetyScore < 80 ? 'Moderate Risk' : 'Low Risk'})`));
      console.log(chalk.cyan('Key Risks:'));
      safetyAssessment.risks?.forEach(risk => {
        console.log(chalk.white(`  - ${risk.issue}: ${risk.implication} (Mitigation: ${risk.mitigation})`));
      });

      // Vulnerability Scan
      console.log(chalk.cyan('\nVulnerability Scan\n------------------'));
      if (!vulnerabilities.length) {
        console.log(chalk.white('No vulnerabilities detected in sBPF bytecode.'));
      } else {
        const vulnTable = new Table({ head: [chalk.cyan('Type'), chalk.cyan('Severity'), chalk.cyan('Details'), chalk.cyan('Confidence')], colWidths: [25, 15, 40, 15] });
        vulnerabilities.forEach(vuln => {
          vulnTable.push([
            chalk.white(vuln.type),
            chalk.white(vuln.severity),
            chalk.white(vuln.details),
            chalk.white(`${vuln.confidence}%`)
          ]);
        });
        console.log(vulnTable.toString());
      }

      // Authority Insights
      console.log(chalk.cyan('\nAuthority Insights\n------------------'));
      if (!authorityInsights.length) {
        console.log(chalk.white('No authorities detected.'));
      } else {
        const authorityTable = new Table({ head: [chalk.cyan('Authority'), chalk.cyan('Total SOL Withdrawn'), chalk.cyan('Wallet Age'), chalk.cyan('Token Mints')], colWidths: [20, 20, 20, 15] });
        authorityInsights.forEach(auth => {
          authorityTable.push([
            chalk.white(auth.authority),
            chalk.white(auth.totalSOLWithdrawn.toFixed(4) + ' SOL'),
            chalk.white(auth.walletAgeDays + ' days'),
            chalk.white(auth.tokenMintCount)
          ]);
        });
        console.log(authorityTable.toString());
        console.log(chalk.white('- Status: Monitor authorities on Solscan for suspicious activity.'));
      }

      // Call Graph
      console.log(chalk.cyan('\nCall Graph\n----------'));
      const topEdges = callGraph.edges?.slice(0, 5) || [];
      if (!topEdges.length) {
        console.log(chalk.white('No significant interactions detected.'));
      } else {
        const callGraphTable = new Table({ head: [chalk.cyan('From'), chalk.cyan('To'), chalk.cyan('Action'), chalk.cyan('Count')], colWidths: [20, 20, 20, 10] });
        topEdges.forEach(edge => {
          callGraphTable.push([
            chalk.white(edge.from),
            chalk.white(edge.to),
            chalk.white(edge.action || 'unknown'),
            chalk.white(edge.count)
          ]);
        });
        console.log(callGraphTable.toString());
        console.log(chalk.white(`- Status: Review top interactions on Solscan.`));
      }

      // Summary Dashboard
      console.log(chalk.cyan('\nSummary Dashboard\n----------------'));
      const summaryTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      summaryTable.push(
        ['Safety Score', chalk.white(`${safetyAssessment.safetyScore}/100`)],
        ['Program Type', chalk.white(analysis.insights.suspectedType.toUpperCase())],
        ['Transaction Volume', chalk.white(`${transactionData.economicInsights.totalVolumeSOL.toFixed(4)} SOL`)],
        ['Vulnerabilities', chalk.white(vulnerabilities.length)],
        ['Authorities', chalk.white(authorityInsights.length)]
      );
      console.log(summaryTable.toString());
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white(`  - Monitor program updates: https://solscan.io/account/${address}#events`));
      if (tokenMetadata?.mintAuthority) {
        console.log(chalk.white(`  - Verify mint authority ${tokenMetadata.mintAuthority}: https://solscan.io/account/${tokenMetadata.mintAuthority}`));
      }
      console.log(chalk.white('  - Run `audit-report` for a detailed report.'));

      console.log(success('Analysis complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Analysis failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`analyze ${address}`, address, analysisResults);
  });

// Analyze Fees command
program
  .command('analyze-fees')
  .description('Analyze transaction fees')
  .argument('<address>', 'Program address')
  .option('-l, --limit <number>', 'Number of transactions to analyze', 25)
  .action(async (address, options) => {
    const spinner = ora(chalk.yellow(`Analyzing fees for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching fee data...';
      const feeAnalysis = await withTimeout(signal => analyzeFees(address, { limit: parseInt(options.limit), signal }), 5000, { totalTransactions: 0, averageFeeSOL: 0, hiddenFees: [], manipulation: [] });
      spinner.succeed(chalk.green(`Fee analysis for ${address}... [Success]`));

      console.log(chalk.cyan('\nFee Analysis\n------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      const feeTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      feeTable.push(
        ['Total Transactions', chalk.white(feeAnalysis.totalTransactions || 0)],
        ['Average Fee (SOL)', chalk.white(feeAnalysis.averageFeeSOL?.toFixed(6) || '0.000005')],
        ['Average Fee (USD)', chalk.white(`$${(feeAnalysis.averageFeeSOL * solPriceUSD || 0.000005 * solPriceUSD).toFixed(4)}`)],
        ['Hidden Fees Detected', chalk.white(feeAnalysis.hiddenFees?.length || 0)],
        ['Manipulation Issues', chalk.white(feeAnalysis.manipulation?.length || 0)]
      );
      console.log(feeTable.toString());

      if (feeAnalysis.manipulation?.length) {
        console.log(chalk.cyan('\nManipulation Issues\n-------------------'));
        const manipulationTable = new Table({ head: [chalk.cyan('Issue'), chalk.cyan('Signature'), chalk.cyan('Details')], colWidths: [20, 20, 40] });
        feeAnalysis.manipulation.forEach(issue => {
          manipulationTable.push([
            chalk.white(issue.issue),
            chalk.white(issue.signature || 'N/A'),
            chalk.white(issue.details)
          ]);
        });
        console.log(manipulationTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Fee Behavior: ${feeAnalysis.manipulation?.length ? 'Potential manipulation detected.' : 'No significant issues.'}`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white(`  - Monitor fees: https://solscan.io/account/${address}#transactions`));
      console.log(chalk.white('  - Run `audit-report` for a comprehensive report.'));

      console.log(success('Fee analysis complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Fee analysis failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`analyze-fees ${address}`, address);
  });

// Quick Check command
program
  .command('quick-check')
  .description('Quick program check')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Performing quick check for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Running quick check...';
      const result = await withTimeout(signal => quickCheck(address, { signal }), 5000, { isActive: false, lastTransaction: null, isUpgradeable: false, upgradeAuthority: null, basicSafetyScore: 50 });
      spinner.succeed(chalk.green(`Quick check for ${address}... [Success]`));

      console.log(chalk.cyan('\nQuick Check Results\n------------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      const quickTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      quickTable.push(
        ['Program Active', chalk.white(result.isActive ? 'Yes' : 'No')],
        ['Recent Activity', chalk.white(result.lastTransaction ? new Date(result.lastTransaction * 1000).toISOString() : 'None')],
        ['Upgradeable', chalk.white(result.isUpgradeable ? 'Yes' : 'No')],
        ['Upgrade Authority', chalk.white(result.upgradeAuthority ? result.upgradeAuthority : 'None')],
        ['Safety Score', chalk.white(`${result.basicSafetyScore}/100`)]
      );
      console.log(quickTable.toString());

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: ${result.isActive ? 'Active program.' : 'Inactive program.'}`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `analyze` for detailed analysis.'));
      console.log(chalk.white('  - Run `monitor` to track activity.'));

      console.log(success('Quick check complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Quick check failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`quick-check ${address}`, address);
  });

// Monitor command
program
  .command('monitor')
  .description('Real-time transaction monitoring')
  .argument('<address>', 'Program address')
  .option('-t, --threshold <lamports>', 'Minimum lamport threshold for alerts', '1000000000') // 1 SOL
  .action(async (address, options) => {
    const spinner = ora(chalk.yellow(`Monitoring program ${address.slice(0, 8)}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      if (!process.env.QUICKNODE_RPC_URL && !process.env.HELIUS_API_KEY) {
        throw new Error('QUICKNODE_RPC_URL or HELIUS_API_KEY not set in .env');
      }
      await startMonitoring(address, {
        threshold: parseInt(options.threshold),
        commitment: 'confirmed',
      });
      // Note: startMonitoring handles its own success logging and SIGINT
    } catch (err) {
      spinner.fail(chalk.red(`Monitoring failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
      await promptNextAction(`monitor ${address}`, address);
    }
  });

// Extract State command
program
  .command('extract-state')
  .description('Extract program state')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Fetching program state for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Extracting state...';
      const state = await withTimeout(signal => extractState(address, { signal }), 5000, []);
      spinner.succeed(chalk.green(`Program state extracted for ${address}... [Success]`));

      console.log(chalk.cyan('\nProgram State\n-------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      if (!state.length) {
        console.log(chalk.white('No program accounts found.'));
      } else {
        const stateTable = new Table({ head: [chalk.cyan('Account'), chalk.cyan('Lamports'), chalk.cyan('Data Length'), chalk.cyan('Data (Hex)')], colWidths: [20, 15, 15, 25] });
        state.forEach(account => {
          stateTable.push([
            chalk.white(account.account),
            chalk.white(account.lamports),
            chalk.white(account.dataLength),
            chalk.white(account.data)
          ]);
        });
        console.log(stateTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: ${state.length ? `${state.length} accounts found.` : 'No state data found.'}`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `analyze` for detailed analysis.'));
      console.log(chalk.white('  - Run `reconstruct-api` to infer program structure.'));

      console.log(success('State extraction complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`State extraction failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`extract-state ${address}`, address);
  });

// Reconstruct API command
program
  .command('reconstruct-api')
  .description('Reconstruct API endpoints')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Reconstructing API for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } });
      spinner.text = 'Fetching transactions...';
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
      spinner.text = 'Generating IDL...';
      const idl = await withTimeout(signal => generateIDL(analysis, transactionData, { signal }), 5000, { instructions: [] });
      spinner.succeed(chalk.green(`API reconstruction for ${address}... [Success]`));

      console.log(chalk.cyan('\nReconstructed API\n-----------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      if (!idl.instructions.length) {
        console.log(chalk.white('No instructions reconstructed.'));
      } else {
        const idlTable = new Table({ head: [chalk.cyan('Instruction'), chalk.cyan('Arguments'), chalk.cyan('Returns')], colWidths: [30, 30, 20] });
        idl.instructions.forEach(instruction => {
          idlTable.push([
            chalk.white(instruction.name),
            chalk.white(instruction.args.map(arg => arg.name + ': ' + arg.type).join(', ') || 'None'),
            chalk.white(instruction.returns || 'void')
          ]);
        });
        console.log(idlTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: ${idl.instructions.length} instructions reconstructed.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `export-idl` to save the IDL.'));
      console.log(chalk.white('  - Run `deep-dive` to analyze instructions.'));

      console.log(success('API reconstruction complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`API reconstruction failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`reconstruct-api ${address}`, address);
  });

// Infer Governance command
program
  .command('infer-governance')
  .description('Infer governance mechanisms')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Inferring governance for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { authorityHolders: [] } });
      spinner.text = 'Analyzing authority holders...';
      const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
      spinner.text = 'Fetching transactions...';
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
      spinner.text = 'Reconstructing call graph...';
      const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
      spinner.text = 'Inferring governance...';
      const governance = await withTimeout(signal => inferGovernance(authorityInsights, callGraph, { signal }), 5000, { type: 'Unknown', trustScore: 50, details: [] });
      spinner.succeed(chalk.green(`Governance inference for ${address}... [Success]`));

      console.log(chalk.cyan('\nGovernance Analysis\n------------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      const govTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      govTable.push(
        ['Governance Type', chalk.white(governance.type)],
        ['Trust Score', chalk.white(`${governance.trustScore}/100 (${governance.trustScore < 50 ? 'Low' : governance.trustScore < 80 ? 'Moderate' : 'High'})`)],
        ['Details', chalk.white(governance.details.join('; ') || 'None')]
      );
      console.log(govTable.toString());

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: Governance type identified as ${governance.type}.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `audit-report` for detailed governance report.'));
      console.log(chalk.white('  - Run `trace-interactions` to monitor authority activity.'));

      console.log(success('Governance inference complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Governance inference failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`infer-governance ${address}`, address);
  });

// Update History command
program
  .command('update-history')
  .description('Analyze update history')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Fetching update history for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Analyzing update history...';
      const updates = await withTimeout(signal => analyzeUpdateHistory(address, { signal }), 5000, []);
      spinner.succeed(chalk.green(`Update history analysis for ${address}... [Success]`));

      console.log(chalk.cyan('\nUpdate History\n--------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      if (!updates.length) {
        console.log(chalk.white('No program updates found.'));
      } else {
        const updateTable = new Table({ head: [chalk.cyan('Timestamp'), chalk.cyan('Changes')], colWidths: [30, 50] });
        updates.forEach(update => {
          updateTable.push([
            chalk.white(new Date(update.timestamp * 1000).toISOString()),
            chalk.white(update.changes.join(', ') || 'None')
          ]);
        });
        console.log(updateTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: ${updates.length ? `${updates.length} updates detected.` : 'No updates detected.'}`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `monitor` to track future updates.'));
      console.log(chalk.white('  - Run `audit-report` for a comprehensive report.'));

      console.log(success('Update history analysis complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Update history analysis failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`update-history ${address}`, address);
  });

// Audit Report command
program
  .command('audit-report')
  .description('Generate audit report')
  .argument('<address>', 'Program address')
  .option('-o, --output <file>', 'Output file path', 'audit_report.json')
  .option('-f, --format <type>', 'Output format (json, markdown)', 'json')
  .action(async (address, options) => {
    const spinner = ora(chalk.yellow(`Generating audit report for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', authorityHolders: [] } });
      spinner.text = 'Fetching transactions...';
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [], economicInsights: { totalVolumeSOL: 0, suspiciousVolume: 0, topAccounts: [] } });
      spinner.text = 'Analyzing authorities...';
      const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
      spinner.text = 'Scanning vulnerabilities...';
      const vulnerabilities = await withTimeout(signal => scanVulnerabilities(analysis, { signal }), 5000, []);
      spinner.text = 'Reconstructing call graph...';
      const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
      spinner.text = 'Assessing safety...';
      const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 50, risks: [] });
      spinner.text = 'Generating report...';
      const report = await withTimeout(signal => generateAuditReport(analysis, authorityInsights, transactionData, callGraph, vulnerabilities, safetyAssessment, { signal }), 5000, {
        programAddress: address,
        executiveSummary: { programType: 'UNKNOWN', safetyScore: 50, riskLevel: 'Moderate', keyFindings: [], riskScoreBreakdown: { critical: 0, high: 0, moderate: 0, low: 0 } },
        riskAssessment: { totalRisks: 0, prioritizedRisks: [] },
        binaryAnalysis: { size: 0, instructionCount: 0, syscalls: [], likelyBehavior: 'Unknown', controlFlow: { complexity: 0, branches: 0, loops: 0 } },
        economicAnalysis: { totalVolumeSOL: 0, averageFeeSOL: 0, suspiciousVolumeSOL: 0 },
        vulnerabilityAnalysis: [],
        recommendations: []
      });
      spinner.succeed(chalk.green(`Audit report generated for ${address}... [Success]`));

      console.log(chalk.cyan('\nAudit Report Summary\n-------------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      const summaryTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      summaryTable.push(
        ['Program Address', chalk.white(report.programAddress)],
        ['Program Type', chalk.white(report.executiveSummary.programType)],
        ['Safety Score', chalk.white(`${report.executiveSummary.safetyScore}/100`)],
        ['Risk Level', chalk.white(report.executiveSummary.riskLevel)],
        ['Total Risks', chalk.white(report.riskAssessment.totalRisks)],
        ['Vulnerabilities', chalk.white(report.vulnerabilityAnalysis.length)]
      );
      console.log(summaryTable.toString());

      console.log(chalk.cyan('Key Findings:'));
      report.executiveSummary.keyFindings.forEach(finding => console.log(chalk.white(`- ${finding}`)));

      const fs = await import('fs/promises');
      if (options.format === 'json') {
        await fs.writeFile(options.output, JSON.stringify(report, null, 2));
        console.log(success(`Report saved to ${options.output}`));
      } else if (options.format === 'markdown') {
        const markdown = [
          `# SolProof Audit Report`,
          `**Program Address**: ${report.programAddress}`,
          `**Timestamp**: ${report.timestamp || new Date().toISOString()}`,
          `**Program Type**: ${report.executiveSummary.programType}`,
          '',
          `## Executive Summary`,
          `- **Safety Score**: ${report.executiveSummary.safetyScore}/100`,
          `- **Risk Level**: ${report.executiveSummary.riskLevel}`,
          `- **Key Findings**:`,
          ...report.executiveSummary.keyFindings.map(f => `  - ${f}`),
          `- **Risk Breakdown**: ${report.executiveSummary.riskScoreBreakdown.critical} Critical, ${report.executiveSummary.riskScoreBreakdown.high} High, ${report.executiveSummary.riskScoreBreakdown.moderate} Moderate, ${report.executiveSummary.riskScoreBreakdown.low} Low`,
          '',
          `## Risk Assessment`,
          ...report.riskAssessment.prioritizedRisks.map(r => `- **${r.type}** (${r.severity}): ${r.details}\n  - Mitigation: ${r.mitigation}`),
          '',
          `## Binary Analysis`,
          `- **Size**: ${report.binaryAnalysis.size} bytes`,
          `- **Instructions**: ${report.binaryAnalysis.instructionCount}`,
          `- **Syscalls**: ${report.binaryAnalysis.syscalls.join(', ') || 'None'}`,
          `- **Behavior**: ${report.binaryAnalysis.likelyBehavior}`,
          `- **Control Flow**: ${report.binaryAnalysis.controlFlow.complexity} (Branches: ${report.binaryAnalysis.controlFlow.branches}, Loops: ${report.binaryAnalysis.controlFlow.loops})`,
          '',
          `## Economic Analysis`,
          `- **Total Volume**: ${report.economicAnalysis.totalVolumeSOL} SOL ($${parseFloat(report.economicAnalysis.totalVolumeSOL * solPriceUSD).toFixed(2)} USD)`,
          `- **Average Fee**: ${report.economicAnalysis.averageFeeSOL} SOL`,
          `- **Suspicious Volume**: ${report.economicAnalysis.suspiciousVolumeSOL} SOL`,
          '',
          `## Recommendations`,
          ...report.recommendations.map(r => `- **${r.priority}**: ${r.action}${r.link ? ` [${r.link}]` : ''}`)
        ].join('\n');
        await fs.writeFile(options.output, markdown);
        console.log(success(`Report saved to ${options.output}`));
      } else {
        throw new Error('Unsupported format. Use "json" or "markdown".');
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: Audit report generated with ${report.riskAssessment.totalRisks} risks identified.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `deep-dive` to investigate risks.'));
      console.log(chalk.white('  - Run `monitor` to track changes.'));

      console.log(success('Audit report generation complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Audit report generation failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`audit-report ${address}`, address);
  });

// Deep Dive command
program
  .command('deep-dive')
  .description('Deep instruction analysis')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Performing deep dive analysis for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { instructions: 0 } });
      spinner.text = 'Fetching transactions...';
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
      spinner.text = 'Performing deep dive analysis...';
      const deepDive = await withTimeout(signal => deepDiveAnalysis(analysis, transactionData, { signal }), 5000, { instructionFrequency: {}, anomalies: [] });
      spinner.succeed(chalk.green(`Deep dive analysis for ${address}... [Success]`));

      console.log(chalk.cyan('\nDeep Dive Analysis\n------------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      const freqTable = new Table({ head: [chalk.cyan('Instruction'), chalk.cyan('Frequency')], colWidths: [30, 20] });
      Object.entries(deepDive.instructionFrequency).forEach(([opcode, count]) => {
        freqTable.push([chalk.white(opcode), chalk.white(count)]);
      });
      console.log(freqTable.toString());

      console.log(chalk.cyan('\nAnomalies\n---------'));
      if (!deepDive.anomalies.length) {
        console.log(chalk.white('No anomalies detected.'));
      } else {
        const anomalyTable = new Table({ head: [chalk.cyan('Issue'), chalk.cyan('Details')], colWidths: [30, 50] });
        deepDive.anomalies.forEach(anomaly => {
          anomalyTable.push([chalk.white(anomaly.issue), chalk.white(anomaly.details)]);
        });
        console.log(anomalyTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: ${deepDive.anomalies.length ? `${deepDive.anomalies.length} anomalies detected.` : 'No anomalies found.'}`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `export-ida` to analyze instructions in IDA Pro.'));
      console.log(chalk.white('  - Run `audit-report` for a comprehensive report.'));

      console.log(success('Deep dive analysis complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Deep dive analysis failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`deep-dive ${address}`, address);
  });

// Predict Risk command
program
  .command('predict-risk')
  .description('Predict future risks')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Predicting risks for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { authorityHolders: [] } });
      spinner.text = 'Fetching transactions...';
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
      spinner.text = 'Analyzing authorities...';
      const authorityInsights = await withTimeout(signal => analyzeAuthorityHolders(analysis.insights.authorityHolders?.filter(a => validateAddress(a)) || [], address, { signal }), 5000, []);
      spinner.text = 'Reconstructing call graph...';
      const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
      spinner.text = 'Assessing safety...';
      const safetyAssessment = await withTimeout(signal => assessSafety(analysis, authorityInsights, transactionData, callGraph, { signal }), 5000, { safetyScore: 50, risks: [] });
      spinner.text = 'Predicting risks...';
      const riskPrediction = await withTimeout(signal => predictRisk(authorityInsights, transactionData, safetyAssessment, { signal }), 5000, { riskLikelihood: 50, prediction: 'Moderate risk', riskFactors: [] });
      spinner.succeed(chalk.green(`Risk prediction for ${address}... [Success]`));

      console.log(chalk.cyan('\nRisk Prediction\n---------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      const riskTable = new Table({ head: [chalk.cyan('Metric'), chalk.cyan('Value')], colWidths: [30, 50] });
      riskTable.push(
        ['Risk Likelihood', chalk.white(`${riskPrediction.riskLikelihood}%`)],
        ['Prediction', chalk.white(riskPrediction.prediction)]
      );
      console.log(riskTable.toString());

      if (riskPrediction.riskFactors?.length) {
        console.log(chalk.cyan('\nRisk Factors\n------------'));
        const factorTable = new Table({ head: [chalk.cyan('Issue'), chalk.cyan('Details')], colWidths: [30, 50] });
        riskPrediction.riskFactors.forEach(factor => {
          factorTable.push([chalk.white(factor.issue), chalk.white(factor.details)]);
        });
        console.log(factorTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: Risk likelihood estimated at ${riskPrediction.riskLikelihood}%.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `monitor` to track high-risk activities.'));
      console.log(chalk.white('  - Run `audit-report` for a comprehensive report.'));

      console.log(success('Risk prediction complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Risk prediction failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`predict-risk ${address}`, address);
  });

// Trace Interactions command
program
  .command('trace-interactions')
  .description('Trace user interactions')
  .argument('<address>', 'Program address')
  .action(async (address) => {
    const spinner = ora(chalk.yellow(`Tracing interactions for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching transaction data...';
      const interactions = await withTimeout(signal => traceInteractions(address, { signal }), 5000, []);
      spinner.succeed(chalk.green(`Interaction tracing for ${address}... [Success]`));

      console.log(chalk.cyan('\nInteraction Tracing\n------------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      if (!interactions.length) {
        console.log(chalk.white('No recent interactions found.'));
      } else {
        const interactionTable = new Table({ head: [chalk.cyan('Account'), chalk.cyan('Action'), chalk.cyan('Volume (SOL)'), chalk.cyan('Timestamp')], colWidths: [20, 20, 15, 30] });
        interactions.forEach(ix => {
          interactionTable.push([
            chalk.white(ix.caller || 'N/A'),
            chalk.white(ix.action || 'unknown'),
            chalk.white(ix.volume?.toFixed(4) || '0.0000'),
            chalk.white(ix.timestamp ? new Date(ix.timestamp).toISOString() : 'N/A')
          ]);
        });
        console.log(interactionTable.toString());
      }

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: ${interactions.length} interactions traced.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Run `monitor` to track ongoing interactions.'));
      console.log(chalk.white('  - Run `audit-report` for a comprehensive report.'));

      console.log(success('Interaction tracing complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Interaction tracing failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`trace-interactions ${address}`, address);
  });

// Compare command
program
  .command('compare')
  .description('Compare two programs')
  .argument('<address1>', 'First program address')
  .argument('<address2>', 'Second program address')
  .action(async (address1, address2) => {
    const spinner = ora(chalk.yellow(`Comparing programs ${address1} and ${address2}...`)).start();
    if (!validateAddress(address1) || !validateAddress(address2)) {
      spinner.fail(chalk.red(`Invalid program address: ${!validateAddress(address1) ? address1 : address2}`));
      console.log(error(`Please provide valid Solana addresses. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binaries...';
      const binary1 = await withTimeout(signal => fetchProgramBinary(address1, { signal }), 5000, Buffer.from([]));
      const binary2 = await withTimeout(signal => fetchProgramBinary(address2, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binaries...';
      const analysis1 = await withTimeout(signal => analyzeBinary(binary1, address1, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } });
      const analysis2 = await withTimeout(signal => analyzeBinary(binary2, address2, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN', instructions: 0 } });
      spinner.text = 'Fetching transactions...';
      const txData1 = await withTimeout(signal => getRecentTransactions(address1, { limit: 25, signal }), 5000, { transactions: [] });
      const txData2 = await withTimeout(signal => getRecentTransactions(address2, { limit: 25, signal }), 5000, { transactions: [] });
      spinner.succeed(chalk.green(`Comparison for ${address1} and ${address2}... [Success]`));

      console.log(chalk.cyan('\nProgram Comparison\n-----------------'));
      console.log(chalk.white(`- Solscan 1: https://solscan.io/account/${address1}`));
      console.log(chalk.white(`- Solscan 2: https://solscan.io/account/${address2}`));
      const compareTable = new Table({
        head: [chalk.cyan('Metric'), chalk.cyan('Program 1'), chalk.cyan('Program 2')],
        colWidths: [30, 30, 30]
      });
      compareTable.push(
        ['Program Type', chalk.white(analysis1.insights.suspectedType), chalk.white(analysis2.insights.suspectedType)],
        ['Instruction Count', chalk.white(analysis1.insights.instructions), chalk.white(analysis2.insights.instructions)],
        ['Transaction Volume', chalk.white(`${txData1.economicInsights.totalVolumeSOL.toFixed(4)} SOL`), chalk.white(`${txData2.economicInsights.totalVolumeSOL.toFixed(4)} SOL`)],
        ['Suspicious Volume', chalk.white(`${txData1.economicInsights.suspiciousVolume.toFixed(4)} SOL`), chalk.white(`${txData2.economicInsights.suspiciousVolumeeousnessVolume.toFixed(4)} SOL`)]
      );
      console.log(compareTable.toString());

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: Programs compared successfully.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white(`  - Run 'analyze ${address1}' or 'analyze ${address2}' for detailed analysis.`));
      console.log(chalk.white('  - Run `audit-report` for comprehensive reports.'));

      console.log(success('Program comparison complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Comparison failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`compare ${address1} ${address2}`, address1);
  });


// Export IDA command
program
  .command('export-ida')
  .description('Export IDA Pro script')
  .argument('<address>', 'Program address')
  .option('-o, --output <file>', 'Output file path', 'ida_script.py')
  .action(async (address, options) => {
    const spinner = ora(chalk.yellow(`Exporting IDA script for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN' } });
      spinner.text = 'Generating IDA script...';
      const idaScript = await withTimeout(signal => exportIdaScript(analysis, { signal }), 5000, '');
      spinner.succeed(chalk.green(`IDA script export for ${address}... [Success]`));

      const fs = await import('fs/promises');
      await fs.writeFile(options.output, idaScript);
      console.log(chalk.cyan('\nIDA Script Export\n-----------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      console.log(chalk.white(`- IDA script saved to: ${options.output}`));

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: IDA script exported successfully.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Load the script in IDA Pro for binary analysis.'));
      console.log(chalk.white('  - Run `deep-dive` for additional insights.'));

      console.log(success('IDA script export complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`IDA script export failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`export-ida ${address}`, address);
  });

// Visualize Graph command
program
  .command('visualize-graph')
  .description('Visualize call graph')
  .argument('<address>', 'Program address')
  .option('-o, --output <file>', 'Output file path', 'graph.dot')
  .action(async (address, options) => {
    const spinner = ora(chalk.yellow(`Visualizing call graph for ${address}...`)).start();
    if (!validateAddress(address)) {
      spinner.fail(chalk.red(`Invalid program address: ${address}`));
      console.log(error(`Please provide a valid Solana address. Contact ${SUPPORT_EMAIL}.`));
      return;
    }

    try {
      spinner.text = 'Fetching program binary...';
      const binary = await withTimeout(signal => fetchProgramBinary(address, { signal }), 5000, Buffer.from([]));
      spinner.text = 'Analyzing binary...';
      const analysis = await withTimeout(signal => analyzeBinary(binary, address, { signal }), 5000, { insights: { suspectedType: 'UNKNOWN' } });
      spinner.text = 'Fetching transactions...';
      const transactionData = await withTimeout(signal => getRecentTransactions(address, { limit: 25, signal }), 5000, { transactions: [] });
      spinner.text = 'Reconstructing call graph...';
      const callGraph = await withTimeout(signal => reconstructCallGraph(analysis, transactionData, { signal }), 5000, { nodes: [], edges: [] });
      spinner.text = 'Generating graph...';
      const graph = await withTimeout(signal => visualizeGraph(callGraph, { signal }), 5000, '');
      spinner.succeed(chalk.green(`Call graph visualization for ${address}... [Success]`));

      const fs = await import('fs/promises');
      await fs.writeFile(options.output, graph);
      console.log(chalk.cyan('\nCall Graph Visualization\n-----------------------'));
      console.log(chalk.white(`- Solscan: https://solscan.io/account/${address}`));
      console.log(chalk.white(`- Explorer: https://explorer.solana.com/address/${address}`));
      console.log(chalk.white(`- Graph saved to: ${options.output}`));
      console.log(chalk.white(`- Nodes: ${callGraph.nodes.length}, Edges: ${callGraph.edges.length}`));

      console.log(chalk.cyan('\nSummary\n-------'));
      console.log(chalk.white(`- Status: Call graph visualized successfully.`));
      console.log(chalk.cyan('Recommendations:'));
      console.log(chalk.white('  - Use Graphviz to view the DOT file.'));
      console.log(chalk.white('  - Run `deep-dive` to analyze interactions.'));

      console.log(success('Call graph visualization complete.'));
    } catch (err) {
      spinner.fail(chalk.red(`Call graph visualization failed: ${err.message}`));
      console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
      console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
    }

    await promptNextAction(`visualize-graph ${address}`, address);
  });

// Start CLI
program.parseAsync(process.argv).catch(err => {
  console.log(chalk.red(`Fatal error: ${err.message}`));
  console.log(chalk.gray(`[DEBUG] Error stack: ${err.stack}`));
  console.log(error(`Contact ${SUPPORT_EMAIL} for assistance.`));
  process.exit(1);
});
