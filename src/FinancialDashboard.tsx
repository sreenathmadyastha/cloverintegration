import React from 'react';
import './FinancialBoard.css';

interface FinancialData {
    moneyIn: {
        paid: number;
        nonInvoicedPayments: number;
        invoicedPayments: number;
        open: {
            receivablesInProgress: number;
            overdueInvoices: number;
        };
        clover: {
            settled: number;
            authorized: number;
        };
    };
    moneyOut: {
        paidBills: number;
        autoPay: number;
        recurring: number;
        single: number;
        scheduled: number;
        open: {
            overdueBills: number;
            unapproved: number;
        };
    };
    total: number;
}


const FinancialDashboard: React.FC<{ data: FinancialData }> = ({ data }) => {


    return (
        <div className="financial-dashboard">
            <div className="section money-in">
                <h2>Money In</h2>
                <ul>
                    <li><span>Paid:</span> ${data.moneyIn.paid.toFixed(2)}</li>
                    <li><span>Non-Invoiced Payments:</span> ${data.moneyIn.nonInvoicedPayments.toFixed(2)}</li>
                    <li><span>Invoiced Payments:</span> ${data.moneyIn.invoicedPayments.toFixed(2)}</li>
                    <li><span>Receivables in Progress:</span> ${data.moneyIn.open.receivablesInProgress.toFixed(2)}</li>
                    <li><span>Overdue Invoices:</span> ${data.moneyIn.open.overdueInvoices.toFixed(2)}</li>
                    <li><span>Settled:</span> ${data.moneyIn.clover.settled.toFixed(2)}</li>
                    <li><span>Authorized:</span> ${data.moneyIn.clover.authorized.toFixed(2)}</li>
                </ul>
            </div>
            <div className="section money-out">
                <h2>Money Out</h2>
                <ul>
                    <li><span>Paid Bills:</span> ${data.moneyOut.paidBills.toFixed(2)}</li>
                    <li><span>Auto Pay:</span> ${data.moneyOut.autoPay.toFixed(2)}</li>
                    <li><span>Recurring:</span> ${data.moneyOut.recurring.toFixed(2)}</li>
                    <li><span>Single:</span> ${data.moneyOut.single.toFixed(2)}</li>
                    <li><span>Scheduled:</span> ${data.moneyOut.scheduled.toFixed(2)}</li>
                    <li><span>Overdue Bills:</span> ${data.moneyOut.open.overdueBills.toFixed(2)}</li>
                    <li><span>Unapproved:</span> ${data.moneyOut.open.unapproved.toFixed(2)}</li>
                </ul>
            </div>
            <div className="total">
                <h2>Total</h2>
                <p>${data.total.toFixed(2)}</p>
            </div>
        </div>
    );
};

export default FinancialDashboard;