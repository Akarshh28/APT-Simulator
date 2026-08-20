import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    // Update state so the next render will show the fallback UI.
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    // You can also log the error to an error reporting service here
    console.error("ErrorBoundary caught an error", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      // Fallback UI
      return (
        <div className="w-full h-full flex items-center justify-center bg-[var(--color-bg-primary)] p-8">
          <div className="bg-[var(--color-bg-card)] border border-[var(--color-danger)] rounded-xl shadow-[0_0_20px_rgba(239,68,68,0.3)] max-w-2xl w-full p-6 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-[var(--color-danger)]"></div>
            <div className="flex items-center gap-3 mb-4">
              <span className="text-3xl">🚨</span>
              <h1 className="text-xl font-bold text-[var(--color-danger)]">Dashboard Render Error</h1>
            </div>
            
            <p className="text-[var(--color-text-dim)] mb-4">
              The application encountered a critical runtime error and was unable to render the UI. 
              The error details are provided below for debugging.
            </p>
            
            <div className="bg-[var(--color-bg-panel)] p-4 rounded-lg overflow-auto max-h-[300px] border border-[var(--color-border-dim)]">
              <pre className="text-xs font-mono text-[var(--color-danger-glow)] whitespace-pre-wrap">
                {this.state.error && this.state.error.toString()}
              </pre>
              <pre className="text-[10px] font-mono text-[var(--color-text-muted)] mt-4 whitespace-pre-wrap">
                {this.state.errorInfo && this.state.errorInfo.componentStack}
              </pre>
            </div>
            
            <div className="mt-6 flex justify-end">
              <button 
                onClick={() => window.location.reload()}
                className="px-4 py-2 bg-[var(--color-bg-hover)] hover:bg-[var(--color-border)] text-white rounded-lg transition-colors font-medium text-sm"
              >
                Reload Dashboard
              </button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children; 
  }
}
