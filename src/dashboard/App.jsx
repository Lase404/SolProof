import React, { useState } from 'react';
import { fetchProgramBinary, analyzeBinary, assessRisks, generateIDL, getRecentTransactions, submitAnalysis } from '../lib';
import introJs from 'intro.js';
import { useTranslation } from 'react-i18next';
import Chart from 'chart.js/auto';
import 'intro.js/introjs.css';

function App() {
  const { t } = useTranslation();
  const [address, setAddress] = useState('');
  const [results, setResults] = useState(null);
  const [risks, setRisks] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [tags, setTags] = useState('');

  const startTutorial = () => {
    introJs().setOptions({
      steps: [
        { element: '#address-input', intro: t('tutorial.enterAddress') },
        { element: '#analyze-button', intro: t('tutorial.analyze') }
      ]
    }).start();
  };

  const analyze = async () => {
    try {
      const binary = await fetchProgramBinary(address);
      const analysis = await analyzeBinary(binary);
      const riskAssessment = assessRisks(analysis);
      const txs = await getRecentTransactions(address);
      setResults(analysis);
      setRisks(riskAssessment);
      setTransactions(txs);

      // Render syscall chart
      const ctx = document.getElementById('syscall-chart')?.getContext('2d');
      if (ctx) {
        new Chart(ctx, {
          type: 'bar',
          data: {
            labels: analysis.syscalls.map(s => s.name),
            datasets: [{ label: t('syscallCount'), data: analysis.syscalls.map(s => s.count) }]
          }
        });
      }
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  const shareToX = () => {
    const text = `Analyzed Solana program ${address} with Solana RE SDK! Risk Score: ${risks.score}/100. @accretion_xyz @SuperteamEarn #SolanaHackathon`;
    window.open(`https://x.com/intent/tweet?text=${encodeURIComponent(text)}`, '_blank');
  };

  const submitToCommunity = async () => {
    try {
      const tagList = tags.split(',').map(tag => tag.trim());
      await submitAnalysis(address, results, risks, tagList);
      alert(t('submitSuccess'));
    } catch (error) {
      alert(`Error: ${error.message}`);
    }
  };

  return (
    <div className="p-4 max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-4">{t('title')}</h1>
      <button onClick={startTutorial} className="mb-4 bg-gray-200 p-2 rounded">
        {t('startTutorial')}
      </button>
      <div className="flex gap-2 mb-4">
        <input
          id="address-input"
          type="text"
          value={address}
          onChange={(e) => setAddress(e.target.value)}
          placeholder={t('enterProgramAddress')}
          className="border p-2 flex-grow"
        />
        <button id="analyze-button" onClick={analyze} className="bg-blue-500 text-white p-2 rounded">
          {t('analyze')}
        </button>
      </div>
      {results && risks && (
        <div>
          <h2 className="text-xl">{t('riskScore')}: {risks.score}/100</h2>
          <canvas id="syscall-chart" className="my-4"></canvas>
          <h3 className="text-lg">{t('risks')}</h3>
          <ul className="list-disc pl-5">
            {risks.risks.map((r, i) => (
              <li key={i}>
                <strong>{r.issue}</strong>: {r.details} ({t('mitigation')}: {r.mitigation})
              </li>
            ))}
          </ul>
          <h3 className="text-lg">{t('transactions')}</h3>
          <ul className="list-disc pl-5">
            {transactions.map((tx, i) => (
              <li key={i}>Transaction {tx.signature.slice(0, 10)}...</li>
            ))}
          </ul>
          <div className="mt-4">
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder={t('enterTags')}
              className="border p-2 mr-2"
            />
            <button onClick={submitToCommunity} className="bg-purple-500 text-white p-2 rounded">
              {t('submitToCommunity')}
            </button>
          </div>
          <button onClick={shareToX} className="mt-4 bg-green-500 text-white p-2 rounded">
            {t('shareToX')}
          </button>
        </div>
      )}
    </div>
  );
}

export default App;