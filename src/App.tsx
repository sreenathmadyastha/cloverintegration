import React, { useState } from 'react';
import axios from 'axios';

interface Payment {
  id: string;
  amount: number;
  tipAmount?: number;
  taxAmount?: number;
  createdTime: number;
  modifiedTime: number;
  result: string;
  // Add more fields as needed from Clover API response
}

const App: React.FC = () => {
  const [merchantId, setMerchantId] = useState<string>('');
  const [token, setToken] = useState<string>('');
  const [payments, setPayments] = useState<Payment[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPayments = async () => {
    if (!merchantId || !token) {
      setError('Please provide merchant ID and OAuth token.');
      return;
    }

    setLoading(true);
    setError(null);

    // Calculate timestamp for 30 days ago (in ms)
    const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;

    try {
      const response = await axios.get(
        `https://apisandbox.dev.clover.com/v3/merchants/${merchantId}/payments?filter=modifiedTime>${thirtyDaysAgo}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json',
          },
        }
      );
      setPayments(response.data.elements || []);  // Clover response has 'elements' array
    } catch (err) {
      setError('Failed to fetch payments. Check token, merchant ID, or network.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ padding: '20px', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Clover Transactions Widget</h1>

      <div>
        <label>
          Merchant ID:
          <input
            type="text"
            value={merchantId}
            onChange={(e) => setMerchantId(e.target.value)}
            style={{ marginLeft: '10px' }}
          />
        </label>
      </div>

      <div style={{ marginTop: '10px' }}>
        <label>
          OAuth Token:
          <input
            type="password"  // Hide token input
            value={token}
            onChange={(e) => setToken(e.target.value)}
            style={{ marginLeft: '10px' }}
          />
        </label>
      </div>

      <button
        onClick={fetchPayments}
        disabled={loading}
        style={{ marginTop: '20px' }}
      >
        {loading ? 'Fetching...' : 'Fetch Transactions'}
      </button>

      {error && <p style={{ color: 'red' }}>{error}</p>}

      {payments.length > 0 && (
        <div style={{ marginTop: '30px' }}>
          <h2>Recent Transactions</h2>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>ID</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Amount ($)</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Tip ($)</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Tax ($)</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Created</th>
                <th style={{ border: '1px solid #ddd', padding: '8px' }}>Result</th>
              </tr>
            </thead>
            <tbody>
              {payments.map((payment) => (
                <tr key={payment.id}>
                  <td style={{ border: '1px solid #ddd', padding: '8px' }}>{payment.id}</td>
                  <td style={{ border: '1px solid #ddd', padding: '8px' }}>{(payment.amount / 100).toFixed(2)}</td>
                  <td style={{ border: '1px solid #ddd', padding: '8px' }}>{(payment.tipAmount ?? 0 / 100).toFixed(2)}</td>
                  <td style={{ border: '1px solid #ddd', padding: '8px' }}>{(payment.taxAmount ?? 0 / 100).toFixed(2)}</td>
                  <td style={{ border: '1px solid #ddd', padding: '8px' }}>{new Date(payment.createdTime).toLocaleString()}</td>
                  <td style={{ border: '1px solid #ddd', padding: '8px' }}>{payment.result}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default App;