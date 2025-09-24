'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function Home() {
    const [ticker, setTicker] = useState<string>('');
    const router = useRouter();

    const handleSearch = (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (ticker.trim()) {
            router.push(`/stock/${ticker.toUpperCase()}`);
        }
    };

    return (
        <div className="container mx-auto p-4">
            <h1 className="text-2xl font-bold mb-4">Stock Price Finder</h1>
            <form onSubmit={handleSearch} className="mb-4">
                <input
                    type="text"
                    value={ticker}
                    onChange={(e) => setTicker(e.target.value)}
                    placeholder="Enter ticker (e.g., AAPL)"
                    className="border p-2 rounded mr-2"
                />
                <button type="submit" className="bg-blue-500 text-white p-2 rounded">
                    Search
                </button>
            </form>
            <p>
                Try popular stocks:{' '}
                <a href="/stock/AAPL" className="text-blue-500">
                    AAPL
                </a>
                ,{' '}
                <a href="/stock/GOOGL" className="text-blue-500">
                    GOOGL
                </a>
            </p>
        </div>
    );
}


// -- File: app/stock/[ticker]/page.tsx (Stock Details with Graph)

import { notFound } from 'next/navigation';
import type { Metadata } from 'next';
import StockGraph from './StockGraph';

// Define stock data type
interface StockData {
    ticker: string;
    name: string;
    prices: number[];
    dates: string[];
}

// Fetch stock data server-side
async function getStockData(ticker: string): Promise<StockData> {
    const response = await fetch(`https://api.example.com/stocks/${ticker}`, {
        next: { revalidate: 86400 }, // Cache for 24 hours (ISR)
        headers: {
            Authorization: `Bearer ${process.env.NEXT_PUBLIC_API_KEY}`, // API key for database access
        },
    });
    if (!response.ok) throw new Error('Failed to fetch stock data');
    return response.json();
}

// Generate SEO metadata
export async function generateMetadata({ params }: { params: { ticker: string } }): Promise<Metadata> {
    const { ticker } = params;
    try {
        const data = await getStockData(ticker);
        return {
            title: `${data.name} (${ticker}) Stock Price - Finance App`,
            description: `View the latest stock price trends for ${data.name} (${ticker}).`,
            openGraph: {
                title: `${data.name} (${ticker}) Stock Price`,
                description: `Explore ${data.name} stock data and price trends.`,
                url: `https://yourapp.com/stock/${ticker}`,
                type: 'website',
            },
        };
    } catch (error) {
        return {
            title: 'Stock Not Found - Finance App',
            description: 'Unable to load stock data.',
        };
    }
}

export default async function StockDetails({ params }: { params: { ticker: string } }) {
    const { ticker } = params;
    let data: StockData;

    try {
        data = await getStockData(ticker);
    } catch (error) {
        notFound();
    }

    return (
        <div className="container mx-auto p-4">
            <h1 className="text-2xl font-bold mb-4">{data.name} ({ticker})</h1>
            <StockGraph initialTicker={ticker} initialData={data} />
        </div>
    );
}