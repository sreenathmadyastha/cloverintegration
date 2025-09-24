'use client';
import { useState, useEffect } from 'react';
import { Line } from 'react-chartjs-2';
import { Chart as ChartJS, LineElement, PointElement, LinearScale, CategoryScale, Title, Tooltip, Legend } from 'chart.js';
import type { ChartData, ChartOptions } from 'chart.js';

// Register Chart.js components
ChartJS.register(LineElement, PointElement, LinearScale, CategoryScale, Title, Tooltip, Legend);

interface StockData {
    ticker: string;
    name: string;
    prices: number[];
    dates: string[];
}

interface StockGraphProps {
    initialTicker: string;
    initialData: StockData;
}

export default function StockGraph({ initialTicker, initialData }: StockGraphProps) {
    const [ticker, setTicker] = useState<string>(initialTicker);
    const [data, setData] = useState<StockData>(initialData);
    const [isLoading, setIsLoading] = useState<boolean>(false);

    useEffect(() => {
        if (ticker !== initialTicker) {
            setIsLoading(true);
            fetch(`https://api.example.com/stocks/${ticker}`, {
                headers: {
                    Authorization: `Bearer ${process.env.NEXT_PUBLIC_API_KEY}`,
                },
            })
                .then((res) => res.json())
                .then((newData: StockData) => {
                    setData(newData);
                    setIsLoading(false);
                })
                .catch(() => setIsLoading(false));
        }
    }, [ticker, initialTicker]);

    const chartData: ChartData<'line'> = {
        labels: data.dates,
        datasets: [
            {
                label: `${data.name} Stock Price`,
                data: data.prices,
                borderColor: '#10b981',
                backgroundColor: 'rgba(16, 185, 129, 0.2)',
                fill: true,
                tension: 0.3,
            },
        ],
    };

    const chartOptions: ChartOptions<'line'> = {
        responsive: true,
        plugins: {
            legend: { position: 'top' },
            title: { display: true, text: `${data.name} (${ticker}) Price Trend` },
        },
        scales: {
            y: { beginAtZero: false, title: { display: true, text: 'Price ($)' } },
            x: { title: { display: true, text: 'Date' } },
        },
    };

    return (
        <div>
            <input
                type="text"
                value={ticker}
                onChange={(e) => setTicker(e.target.value.toUpperCase())}
                placeholder="Enter new ticker"
                className="border p-2 rounded mb-4"
            />
            <div className="max-w-2xl mx-auto">
                {isLoading ? (
                    <div className="animate-pulse">
                        <div className="h-64 bg-gray-200 rounded"></div>
                    </div>
                ) : (
                    ```chartjs
          {
            "type": "line",
            "data": {
              "labels": ${JSON.stringify(data.dates)},
              "datasets": [
                {
                  "label": "${data.name} Stock Price",
                  "data": ${JSON.stringify(data.prices)},
                  "borderColor": "#10b981",
                  "backgroundColor": "rgba(16, 185, 129, 0.2)",
                  "fill": true,
                  "tension": 0.3
                }
              ]
            },
            "options": {
              "responsive": true,
              "plugins": {
                "legend": { "position": "top" },
                "title": { "display": true, "text": "${data.name} (${ticker}) Price Trend" }
              },
              "scales": {
                "y": { "beginAtZero": false, "title": { "display": true, "text": "Price ($)" } },
                "x": { "title": { "display": true, "text": "Date" } }
              }
            }
          }
          ```
                )}
            </div>
        </div>
    );
}