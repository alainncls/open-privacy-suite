import { ErrorInfo, Component, ReactNode } from 'react';
import { Outlet, useLocation, useNavigate } from 'react-router-dom';
import { Tabs, TabsList, TabsTrigger } from './components/ui/tabs';
import { Shield, LayoutDashboard, ScrollText, Users, FileKey, Scale } from 'lucide-react';

type Tab = 'dashboard' | 'logs' | 'rbac' | 'compliance' | 'disclosure';

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
        <div className="min-h-screen bg-[#F1F5F9] flex items-center justify-center p-8">
          <div className="bg-white border border-[#E2E8F0] rounded-xl shadow-card p-8 text-center max-w-md animate-fade-in">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#FEE2E2] flex items-center justify-center">
              <Shield className="w-8 h-8 text-[#991B1B]" />
            </div>
            <h2 className="text-xl font-semibold text-[#0F0F0F] mb-2">Something went wrong</h2>
            <p className="text-[#6B7280] mb-6">
              {this.state.error?.message || 'An unexpected error occurred'}
            </p>
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-2.5 bg-[#8950FA] text-white rounded-full hover:bg-[#6B3DD4] transition-colors hover:shadow-primary"
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
    if (location.pathname.includes('/compliance')) return 'compliance';
    if (location.pathname.includes('/disclosure')) return 'disclosure';
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
      case 'compliance':
        navigate('/admin/compliance');
        break;
      case 'disclosure':
        navigate('/admin/disclosure');
        break;
    }
  };

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-[#F1F5F9]" data-testid="admin-app">
        {/* Navigation Header */}
        <header className="bg-white border-b border-[#E2E8F0] shadow-sm sticky top-0 z-40" data-testid="admin-header">
          <div className="max-w-7xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              {/* Logo and Title */}
              <div className="flex items-center gap-3" data-testid="admin-logo">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#8950FA] to-[#A478FC] flex items-center justify-center shadow-primary">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h1 className="text-lg font-semibold text-[#0F0F0F]">Privacy Proxy</h1>
                  <p className="text-xs text-[#6B7280]">Node Access Control</p>
                </div>
              </div>

              {/* Navigation Tabs */}
              <Tabs value={activeTab} onValueChange={handleTabChange} data-testid="admin-nav">
                <TabsList>
                  <TabsTrigger value="dashboard" className="gap-2" data-testid="nav-dashboard">
                    <LayoutDashboard className="w-4 h-4" />
                    <span className="hidden sm:inline">Dashboard</span>
                  </TabsTrigger>
                  <TabsTrigger value="logs" className="gap-2" data-testid="nav-logs">
                    <ScrollText className="w-4 h-4" />
                    <span className="hidden sm:inline">Access Logs</span>
                  </TabsTrigger>
                  <TabsTrigger value="rbac" className="gap-2" data-testid="nav-rbac">
                    <Users className="w-4 h-4" />
                    <span className="hidden sm:inline">RBAC</span>
                  </TabsTrigger>
                  <TabsTrigger value="compliance" className="gap-2">
                    <Scale className="w-4 h-4" />
                    <span className="hidden sm:inline">Compliance</span>
                  </TabsTrigger>
                  <TabsTrigger value="disclosure" className="gap-2">
                    <FileKey className="w-4 h-4" />
                    <span className="hidden sm:inline">Disclosure</span>
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
