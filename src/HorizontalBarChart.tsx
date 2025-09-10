import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from 'recharts';

interface ChartData {
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

const HorizontalBarChart: React.FC<{ data: ChartData }> = ({ data }) => {
    const chartData = [
        { name: 'Paid', value: data.moneyIn.paid },
        { name: 'Open', value: data.moneyIn.open.receivablesInProgress + data.moneyIn.open.overdueInvoices },
        { name: 'Clover', value: data.moneyIn.clover.settled + data.moneyIn.clover.authorized },
    ];

    return (
        <div>
            <h2 className="text-xl font-semibold mb-2">Money In Horizontal Bar Chart</h2>
            <BarChart
                width={600}
                height={300}
                data={chartData}
                layout="vertical"
                margin={{ top: 20, right: 30, left: 20, bottom: 5 }}
            >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="name" type="category" />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" fill="#4B5EAA" />
            </BarChart>
        </div>
    );
};

export default HorizontalBarChart;