import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import './index.css'

import FinancialDashboard from './FinancialDashboard.tsx'
import HorizontalBarChart from './HorizontalBarChart.tsx'
import HorizontalBarLayout from './HorizontalBarLayout.tsx'


const financeData = {
  moneyIn: {
    paid: 8.29,
    nonInvoicedPayments: 0,
    invoicedPayments: 14329,
    open: {
      receivablesInProgress: 300,
      overdueInvoices: 4000,
    },
    clover: {
      settled: 1508,
      authorized: 2500,
    },
  },
  moneyOut: {
    paidBills: 0,
    autoPay: 0,
    recurring: 0,
    single: 0,
    scheduled: 0,
    open: {
      overdueBills: 0,
      unapproved: 0,
    },
  },
  total: 1637,
};

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    {/* <App /> */}

    <FinancialDashboard data={financeData} />
    <HorizontalBarChart data={financeData} />

    <HorizontalBarLayout data={financeData} />

  </React.StrictMode>,
)