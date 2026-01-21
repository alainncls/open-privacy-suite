import { ErrorInfo, Component, ReactNode } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger } from './components/ui/tabs';
import { Shield, LayoutDashboard, ScrollText, Users } from 'lucide-react';

type Tab = 'dashboard' | 'logs' | 'rbac';

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
        <div className="min-h-screen flex items-center justify-center p-8">
          <div className="glass-card-solid p-8 text-center max-w-md animate-fade-in">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/20 flex items-center justify-center">
              <Shield className="w-8 h-8 text-red-400" />
            </div>
            <h2 className="text-xl font-semibold text-white/90 mb-2">Something went wrong</h2>
            <p className="text-white/60 mb-6">
              {this.state.error?.message || 'An unexpected error occurred'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2.5 bg-primary-600 text-white rounded-lg hover:bg-primary-500 transition-colors shadow-lg shadow-primary-500/25"
            >
              Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

function App() {
  const location = useLocation();
  const navigate = useNavigate();

  // Derive active tab from URL
  const getActiveTab = (): Tab => {
    if (location.pathname.includes('/logs')) return 'logs';
    if (location.pathname.includes('/rbac')) return 'rbac';
    return 'dashboard';
  };

  const activeTab = getActiveTab();

  const handleTabChange = (value: string) => {
    switch (value) {
      case 'dashboard':
        navigate('/admin/dashboard');
        break;
      case 'logs':
        navigate('/admin/logs');
        break;
      case 'rbac':
        navigate('/admin/rbac');
        break;
    }
  };

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-mesh">
        {/* Glass Navigation Header */}
        <header className="glass-nav sticky top-0 z-40">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Logo and Title */}
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shadow-lg shadow-primary-500/30">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h1 className="text-lg font-semibold text-white/95">Privacy Proxy</h1>
                  <p className="text-xs text-white/60">Node Access Control</p>
                </div>
              </div>

              {/* Navigation Tabs */}
              <Tabs value={activeTab} onValueChange={handleTabChange}>
                <TabsList className="bg-white/5">
                  <TabsTrigger value="dashboard" className="gap-2">
                    <LayoutDashboard className="w-4 h-4" />
                    <span className="hidden sm:inline">Dashboard</span>
                  </TabsTrigger>
                  <TabsTrigger value="logs" className="gap-2">
                    <ScrollText className="w-4 h-4" />
                    <span className="hidden sm:inline">Access Logs</span>
                  </TabsTrigger>
                  <TabsTrigger value="rbac" className="gap-2">
                    <Users className="w-4 h-4" />
                    <span className="hidden sm:inline">RBAC</span>
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-6 py-8">
          <div className="animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>
    </ErrorBoundary>
  );
}

export default App;
