import { useState, ErrorInfo, Component, ReactNode } from 'react';
import PolicyList from './components/PolicyList';
import AccessLogs from './components/AccessLogs';
import './App.css';

type Tab = 'policies' | 'logs';

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<{ children: ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('React Error Boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '2rem', textAlign: 'center' }}>
          <h2>Something went wrong</h2>
          <p>{this.state.error?.message || 'An unexpected error occurred'}</p>
          <button onClick={() => window.location.reload()}>Reload Page</button>
        </div>
      );
    }

    return this.props.children;
  }
}

function App() {
  const [activeTab, setActiveTab] = useState<Tab>('policies');

  return (
    <ErrorBoundary>
      <div className="App">
        <header>
          <h1>Privacy Proxy Dashboard</h1>
          <p>Access control management for Erigon node</p>
        </header>

        <nav style={{ marginBottom: '2rem', borderBottom: '1px solid #ccc' }}>
          <button
            onClick={() => setActiveTab('policies')}
            style={{
              padding: '0.5rem 1rem',
              marginRight: '0.5rem',
              border: 'none',
              background: activeTab === 'policies' ? '#007bff' : 'transparent',
              color: activeTab === 'policies' ? 'white' : 'inherit',
              cursor: 'pointer',
            }}
          >
            Policies
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            style={{
              padding: '0.5rem 1rem',
              border: 'none',
              background: activeTab === 'logs' ? '#007bff' : 'transparent',
              color: activeTab === 'logs' ? 'white' : 'inherit',
              cursor: 'pointer',
            }}
          >
            Access Logs
          </button>
        </nav>

        <main>
          {activeTab === 'policies' && <PolicyList />}
          {activeTab === 'logs' && <AccessLogs />}
        </main>
      </div>
    </ErrorBoundary>
  );
}

export default App;
