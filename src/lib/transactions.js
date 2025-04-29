import { Connection, PublicKey } from '@solana/web3.js';
import fetch from 'node-fetch';
import NodeCache from 'node-cache';
import Bottleneck from 'bottleneck';
import chalk from 'chalk';
import dotenv from 'dotenv';

dotenv.config();

const cache = new NodeCache({ stdTTL: 600 }); // Cache for 10 minutes
const limiter = new Bottleneck({ minTime: 2000 }); // 1 request every 2 seconds
const fetchWithLimit = limiter.wrap(fetch);

/**
 * Fetches recent transactions for a Solana program using Helius RPC with rate-limiting.
 * Analyzes transaction volume, types, and token flows for economic insights.
 *
 * @param {string} address - The program address.
 * @param {Object} options - Options for transaction fetching.
 * @param {number} options.limit - Number of transactions to fetch (default: 10).
 * @param {string} options.timeframe - Timeframe for transactions (e.g., '7d', default: '7d').
 * @returns {Promise<Object>} - Transaction data with economic insights.
 * @throws {Error} - If API key is missing or fetching fails after retries.
 */
export async function getRecentTransactions(address, options = {}) {
  const { limit = 10, timeframe = '7d' } = options;
  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  const cacheKey = `tx_${address}_${limit}_${timeframe}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const maxRetries = 5;
  const retryDelays = [1000, 2000, 4000, 8000, 16000];
  const url = `https://api.helius.xyz/v0/addresses/${address}/transactions?api-key=${apiKey}&limit=${limit}`;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetchWithLimit(url);
      if (response.status === 429) {
        if (attempt === maxRetries) throw new Error('Rate limit exceeded for transaction fetching');
        await new Promise(resolve => setTimeout(resolve, retryDelays[attempt]));
        continue;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);

      const txs = await response.json();
      if (!Array.isArray(txs)) throw new Error('Invalid transaction data from Helius');

      const connection = new Connection(`https://mainnet.helius-rpc.com/?api-key=${apiKey}`, 'confirmed');
      const transactions = await Promise.all(
        txs.map(async tx => {
          const parsedTx = await limiter.schedule(() =>
            connection.getParsedTransaction(tx.signature, {
              commitment: 'confirmed',
              maxSupportedTransactionVersion: 0,
            })
          );
          return {
            signature: tx.signature,
            slot: tx.slot,
            blockTime: tx.timestamp,
            instructions: parsedTx?.transaction.message.instructions || [],
            isNonStandard: !parsedTx?.transaction.message.instructions.some(ix => ix.programId.toBase58() === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'),
            type: inferTransactionType(parsedTx, address),
            details: parsedTx,
            meta: {
              volumeSOL: parsedTx?.meta ? Math.abs((parsedTx.meta.preBalances[0] - parsedTx.meta.postBalances[0]) / 1e9) || 0 : 0,
              fee: parsedTx?.meta?.fee / 1e9 || 0,
            },
          };
        })
      );

      const tokenFlowInsights = await limiter.schedule(() => analyzeTokenFlows(transactions, address));

      const volumes = transactions.map(tx => tx.meta.volumeSOL || 0);
      const meanVolumeSOL = volumes.length ? volumes.reduce((sum, vol) => sum + vol, 0) / volumes.length : 0;
      const stdDevVolumeSOL = volumes.length
        ? Math.sqrt(volumes.reduce((sum, vol) => sum + Math.pow(vol - meanVolumeSOL, 2), 0) / volumes.length)
        : 0;

      const economicInsights = {
        totalVolumeSOL: transactions.reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0),
        averageFeeSOL: transactions.reduce((sum, tx) => sum + (tx.meta.fee || 0), 0) / (transactions.length || 1),
        transactionCount: transactions.length,
        transactionTypes: {
          swaps: { count: transactions.filter(tx => tx.type === 'swap').length, volumeSOL: transactions.filter(tx => tx.type === 'swap').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
          transfers: { count: transactions.filter(tx => tx.type === 'transfer').length, volumeSOL: transactions.filter(tx => tx.type === 'transfer').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
          mints: { count: transactions.filter(tx => tx.type === 'mint').length, volumeSOL: transactions.filter(tx => tx.type === 'mint').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
          burns: { count: transactions.filter(tx => tx.type === 'burn').length, volumeSOL: transactions.filter(tx => tx.type === 'burn').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
          governance: { count: transactions.filter(tx => tx.type === 'governance').length, volumeSOL: transactions.filter(tx => tx.type === 'governance').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
          nftMints: { count: transactions.filter(tx => tx.type === 'nft_mint').length, volumeSOL: transactions.filter(tx => tx.type === 'nft_mint').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
          others: { count: transactions.filter(tx => tx.type === 'unknown' || tx.type === 'custom').length, volumeSOL: transactions.filter(tx => tx.type === 'unknown' || tx.type === 'custom').reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0) },
        },
        suspiciousVolume: transactions.filter(tx => tx.isNonStandard).reduce((sum, tx) => sum + (tx.meta.volumeSOL || 0), 0),
        tokenFlowInsights,
        transactionVolumeAnalysis: {
          meanVolumeSOL,
          stdDevVolumeSOL,
          highVolatility: stdDevVolumeSOL > meanVolumeSOL * 0.5,
        },
      };

      const result = { transactions, economicInsights };
      cache.set(cacheKey, result);
      return result;
    } catch (err) {
      if (attempt === maxRetries) {
        console.warn(chalk.yellow(`Failed to fetch transactions for ${address}: ${err.message}`));
        return createFallback();
      }
      await new Promise(resolve => setTimeout(resolve, retryDelays[attempt]));
    }
  }

  console.warn(chalk.yellow(`Unexpected exit in transaction fetch for ${address}`));
  return createFallback();
}

/**
 * Creates a fallback transaction object for error cases.
 * @returns {Object} - Fallback transaction data.
 */
function createFallback() {
  return {
    transactions: [],
    economicInsights: {
      totalVolumeSOL: 0,
      averageFeeSOL: 0,
      transactionCount: 0,
      transactionTypes: {
        swaps: { count: 0, volumeSOL: 0 },
        transfers: { count: 0, volumeSOL: 0 },
        mints: { count: 0, volumeSOL: 0 },
        burns: { count: 0, volumeSOL: 0 },
        governance: { count: 0, volumeSOL: 0 },
        nftMints: { count: 0, volumeSOL: 0 },
        others: { count: 0, volumeSOL: 0 },
      },
      suspiciousVolume: 0,
      tokenFlowInsights: { topOutflows: [], topInflows: [], concentrationRisk: false },
      transactionVolumeAnalysis: { meanVolumeSOL: 0, stdDevVolumeSOL: 0, highVolatility: false },
    },
  };
}

/**
 * Fetches token metadata for a mint address using Helius RPC.
 * @param {string} mint - The token mint address.
 * @returns {Promise<Object>} - Token metadata.
 */
export async function getTokenMetadata(mint) {
  if (!mint || mint === 'SOL' || mint === 'GOVERNANCE') {
    return { name: 'None', mint: 'None', supply: 'Unknown', decimals: 9, mintAuthority: null, freezeAuthority: null };
  }

  const cacheKey = `token_${mint}`;
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  const apiKey = process.env.HELIUS_API_KEY;
  if (!apiKey) throw new Error('HELIUS_API_KEY not set in .env');

  const maxRetries = 5;
  const retryDelays = [1000, 2000, 4000, 8000, 16000];
  const url = `https://api.helius.xyz/v0/tokens/metadata?api-key=${apiKey}`;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetchWithLimit(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mintAccounts: [mint] }),
      });

      if (response.status === 429) {
        if (attempt === maxRetries) throw new Error(`Rate limit exceeded for token metadata on ${mint}`);
        await new Promise(resolve => setTimeout(resolve, retryDelays[attempt]));
        continue;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${await response.text()}`);

      const metadataArray = await response.json();
      const metadata = metadataArray[0] || {};
      const result = {
        name: metadata.onChainMetadata?.metadata?.data?.name || 'Unknown',
        mint,
        supply: metadata.onChainMetadata?.metadata?.supply
          ? (metadata.onChainMetadata.metadata.supply / Math.pow(10, metadata.onChainMetadata.metadata.decimals || 9)).toString()
          : 'Unknown',
        decimals: metadata.onChainMetadata?.metadata?.decimals || 9,
        mintAuthority: metadata.onChainMetadata?.mintAuthority || null,
        freezeAuthority: metadata.onChainMetadata?.freezeAuthority || null,
      };
      cache.set(cacheKey, result);
      return result;
    } catch (err) {
      if (attempt === maxRetries) {
        console.warn(chalk.yellow(`Failed to fetch token metadata for ${mint}: ${err.message}`));
        return { name: 'Unknown', mint, supply: 'Unknown', decimals: 9, mintAuthority: null, freezeAuthority: null };
      }
      await new Promise(resolve => setTimeout(resolve, retryDelays[attempt]));
    }
  }

  return { name: 'Unknown', mint, supply: 'Unknown', decimals: 9, mintAuthority: null, freezeAuthority: null };
}

/**
 * Infers the type of a transaction based on parsed data and program context.
 * @param {Object} parsedTx - The parsed transaction data.
 * @param {string} programAddress - The program address for context.
 * @returns {string} - The inferred transaction type.
 */
function inferTransactionType(parsedTx, programAddress) {
  if (!parsedTx) return 'unknown';
  const instructions = parsedTx.transaction.message.instructions;

  if (instructions.some(ix =>
    ix.programId.toBase58() === 'GovER5Lthms3bLBqWub97yVrMmEogzX7xNjdXpPPCVZw' ||
    ix.programId.toBase58() === 'SMPLecHpvtyTWca6gwQLoCFN33w41rmatZTxM4W3fS7' ||
    ix.parsed?.type === 'createProposal' ||
    ix.parsed?.type === 'vote'
  )) {
    return 'governance';
  }

  if (instructions.some(ix => ix.programId.toBase58() === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')) {
    const tokenIx = instructions.find(ix => ix.programId.toBase58() === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
    if (tokenIx.parsed?.type === 'transfer') return 'transfer';
    if (tokenIx.parsed?.type === 'mint') return 'mint';
    if (tokenIx.parsed?.type === 'burn') return 'burn';
  }

  if (instructions.some(ix => [
    '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8', // Raydium
    'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA', // Pump.fun
    programAddress,
  ].includes(ix.programId.toBase58()))) {
    return 'swap';
  }

  if (instructions.some(ix =>
    ix.programId.toBase58() === 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s' ||
    ix.parsed?.type === 'mintNFT'
  )) {
    return 'nft_mint';
  }

  if (instructions.some(ix => ix.programId.toBase58() === programAddress)) {
    return 'custom';
  }

  return 'unknown';
}

/**
 * Analyzes token and account flows from transactions.
 * @param {Array} transactions - The list of transactions.
 * @param {string} address - The program address.
 * @returns {Promise<Object>} - Flow insights.
 */
async function analyzeTokenFlows(transactions, address) {
  const outflows = [];
  const inflows = [];
  let concentrationRisk = false;

  for (const tx of transactions) {
    if (!tx.details) continue;
    const instructions = tx.instructions;

    for (const ix of instructions) {
      let flowType = null;
      let source, destination, amount, mint;

      if (ix.programId?.toBase58() === 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA' && ix.parsed?.type === 'transfer') {
        ({ source, destination, amount, mint } = ix.parsed.info);
        flowType = 'transfer';
      } else if (['swap', 'custom'].includes(tx.type) && ix.accounts?.length >= 2) {
        source = ix.accounts[0]?.toBase58();
        destination = ix.accounts[1]?.toBase58();
        amount = tx.meta?.volumeSOL || 1;
        mint = ix.parsed?.info?.mint || 'SOL';
        flowType = 'swap';
      } else if (tx.type === 'governance' && ix.accounts?.length >= 1) {
        source = ix.accounts[0]?.toBase58();
        destination = address;
        amount = 1;
        mint = 'GOVERNANCE';
        flowType = 'vote';
      } else if (tx.type === 'nft_mint' && ix.parsed?.info?.mint) {
        source = address;
        destination = ix.parsed.info.mintAuthority || ix.accounts[0]?.toBase58();
        amount = 1;
        mint = ix.parsed.info.mint;
        flowType = 'nft_mint';
      }

      if (flowType && source && destination) {
        const parsedAmount = mint === 'SOL' || mint === 'GOVERNANCE' ? amount : parseFloat(amount) / Math.pow(10, await getTokenDecimals(mint));
        if (source === address) {
          outflows.push({ account: destination, amount: parsedAmount, token: mint, mint, flowType, txCount: 1 });
        } else if (destination === address) {
          inflows.push({ account: source, amount: parsedAmount, token: mint, mint, flowType, txCount: 1 });
        }
      }
    }
  }

  const aggregateFlows = (flows) =>
    Object.values(
      flows.reduce((acc, flow) => {
        const key = `${flow.account}_${flow.mint}_${flow.flowType}`;
        if (!acc[key]) acc[key] = { ...flow, amount: 0, txCount: 0 };
        acc[key].amount += flow.amount;
        acc[key].txCount += 1;
        return acc;
      }, {})
    ).sort((a, b) => b.amount - a.amount);

  const topOutflows = aggregateFlows(outflows).slice(0, 5);
  const topInflows = aggregateFlows(inflows).slice(0, 5);
  if (topOutflows.length > 0 && topOutflows[0].amount > 0.8 * topOutflows.reduce((sum, f) => sum + f.amount, 0)) {
    concentrationRisk = true;
  }

  return { topOutflows, topInflows, concentrationRisk };
}

/**
 * Fetches token decimals for a mint address.
 * @param {string} mint - The token mint address.
 * @returns {Promise<number>} - The number of decimals.
 */
async function getTokenDecimals(mint) {
  if (mint === 'SOL' || mint === 'GOVERNANCE') return 9;
  const metadata = await getTokenMetadata(mint);
  return metadata.decimals !== 'Unknown' ? parseInt(metadata.decimals) : 9;
}

/**
 * Analyzes transaction fees for hidden fees or manipulation.
 * @param {string} address - The program address.
 * @param {Object} options - Options for analysis.
 * @param {number} options.limit - Number of transactions to analyze.
 * @returns {Promise<Object>} - Fee analysis results.
 */
export async function analyzeFees(address, options = {}) {
  const { limit = 25 } = options;
  try {
    const { transactions } = await getRecentTransactions(address, { limit });
    const fees = transactions.map(tx => ({
      signature: tx.signature,
      fee: tx.meta?.fee / 1e9 || 0,
    }));

    const averageFeeSOL = fees.reduce((sum, tx) => sum + tx.fee, 0) / (fees.length || 1);
    const feeThreshold = averageFeeSOL * 3;

    const hiddenFees = [];
    const manipulation = fees
      .filter(tx => tx.fee > feeThreshold)
      .map(tx => ({
        issue: 'Fee Spike',
        signature: tx.signature,
        details: `Fee ${tx.fee.toFixed(6)} SOL exceeds average (${averageFeeSOL.toFixed(6)} SOL)`,
      }));

    return {
      totalTransactions: transactions.length,
      averageFeeSOL,
      hiddenFees,
      manipulation,
    };
  } catch (err) {
    console.warn(chalk.yellow(`Fee analysis failed for ${address}: ${err.message}`));
    return {
      totalTransactions: 0,
      averageFeeSOL: 0,
      hiddenFees: [],
      manipulation: [],
    };
  }
}