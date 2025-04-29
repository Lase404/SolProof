import { initializeApp } from 'firebase/app';
import { getFirestore, collection, addDoc, getDocs } from 'firebase/firestore';
import { firebaseConfig } from '../config/firebase.js';

const app = initializeApp(firebaseConfig);
const db = getFirestore(app);

export async function submitAnalysis(address, analysis, risks, tags = []) {
  try {
    await addDoc(collection(db, 'programs'), {
      address,
      analysis,
      risks,
      tags,
      timestamp: new Date()
    });
  } catch (error) {
    throw new Error(`Failed to submit analysis: ${error.message}`);
  }
}

export async function searchPrograms(tag) {
  try {
    const querySnapshot = await getDocs(collection(db, 'programs'));
    return querySnapshot.docs
      .map(doc => doc.data())
      .filter(data => data.tags?.includes(tag));
  } catch (error) {
    throw new Error(`Failed to search programs: ${error.message}`);
  }
}