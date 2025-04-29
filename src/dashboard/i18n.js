import i18next from 'i18next';
import { initReactI18next } from 'react-i18next';

i18next.use(initReactI18next).init({
  resources: {
    en: {
      translation: {
        title: 'Solana Reverse Engineering SDK',
        enterProgramAddress: 'Enter program address',
        analyze: 'Analyze',
        riskScore: 'Risk Score',
        risks: 'Risks',
        mitigation: 'Mitigation',
        shareToX: 'Share to X',
        startTutorial: 'Start Tutorial',
        submitToCommunity: 'Submit to Community',
        enterTags: 'Enter tags (e.g., AMM, Risky)',
        submitSuccess: 'Analysis submitted successfully!',
        syscallCount: 'Syscall Count',
        transactions: 'Recent Transactions',
        tutorial: {
          enterAddress: 'Enter a Solana program address here.',
          analyze: 'Click to analyze the program’s .'
        }
      }
    },
    yo: {
      translation: {
        title: 'Solana Reverse Engineering SDK',
        enterProgramAddress: 'Tẹ adirẹsi eto sii',
        analyze: 'Ṣe Ìtúpalẹ̀',
        riskScore: 'Idiwọn Ewu',
        risks: 'Awọn ewu',
        mitigation: 'Idinku',
        shareToX: 'Pin si X',
        startTutorial: 'Bẹrẹ Ikẹkọ',
        submitToCommunity: 'Fi si Agbegbe',
        enterTags: 'Tẹ awọn ami sii (e.g., AMM, Ewu)',
        submitSuccess: 'Ìtúpalẹ̀ ti fi silẹ ni aṣeyọri!',
        syscallCount: 'Idiwọn Syscall',
        transactions: 'Awọn Idunadura Aipẹ',
        tutorial: {
          enterAddress: 'Tẹ adirẹsi eto Solana sii nibi.',
          analyze: 'Tẹ lati ṣe itupalẹ  eto naa.'
        }
      }
    }
  },
  lng: 'en',
  fallbackLng: 'en'
});

export default i18next;