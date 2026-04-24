import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false };

  static getDerivedStateFromError(): State {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Unhandled frontend error", { error, info });
  }

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <main className="fallback-screen">
          <h1>Something went wrong</h1>
          <p>The local application shell could not render.</p>
        </main>
      );
    }

    return this.props.children;
  }
}

