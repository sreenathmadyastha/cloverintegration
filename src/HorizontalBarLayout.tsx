import React from 'react';
import './HorizontalBarLayout.css';

interface BarData {
    moneyIn: {
        paid: number;
        open: {
            receivablesInProgress: number;
            overdueInvoices: number;
        };
        clover: {
            settled: number;
            authorized: number;
        };
    };
}

const HorizontalBarLayout: React.FC<{ data: BarData }> = ({ data }) => {
    const maxValue = Math.max(data.moneyIn.paid, data.moneyIn.open.receivablesInProgress + data.moneyIn.open.overdueInvoices, data.moneyIn.clover.settled + data.moneyIn.clover.authorized);
    const getWidthPercentage = (value: number) => (value / maxValue) * 100;

    return (
        <div>
            <h2 className="text-xl font-semibold mb-2">Money In Horizontal Bars</h2>
            <div className="bar-container">
                <div className="bar paid-bar" style={{ width: `${getWidthPercentage(data.moneyIn.paid)}%` }}>
                    <span>Paid: ${data.moneyIn.paid.toFixed(2)}</span>
                </div>
                <div className="bar open-bar" style={{ width: `${getWidthPercentage(data.moneyIn.open.receivablesInProgress + data.moneyIn.open.overdueInvoices)}%` }}>
                    <span>Open: ${(data.moneyIn.open.receivablesInProgress + data.moneyIn.open.overdueInvoices).toFixed(2)}</span>
                </div>
                <div className="bar clover-bar" style={{ width: `${getWidthPercentage(data.moneyIn.clover.settled + data.moneyIn.clover.authorized)}%` }}>
                    <span>Clover: ${(data.moneyIn.clover.settled + data.moneyIn.clover.authorized).toFixed(2)}</span>
                </div>
            </div>
        </div>
    );
};

export default HorizontalBarLayout;