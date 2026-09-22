import type { ReactNode } from 'react';
import { useBreakpoint } from '../../hooks/useBreakpoint';

export function ResponsiveLayout({ children }: { children: ReactNode }) {
  const breakpoint = useBreakpoint();
  const padding = breakpoint === 'mobile' ? '14px' : breakpoint === 'tablet' ? '20px' : '28px';
  return (
    <div className="responsive-layout" style={{ padding }}>
      {children}
    </div>
  );
}

export function MobileNav({
  tabs,
  activeTab,
  onSelect,
}: {
  tabs: { key: string; icon: string; label: string }[];
  activeTab: string;
  onSelect: (tab: string) => void;
}) {
  return (
    <nav className="mobile-nav" aria-label="Mobile navigation">
      {tabs.map((tab) => (
        <button
          key={tab.key}
          type="button"
          className={`mobile-nav-item ${activeTab === tab.key ? 'active' : ''}`}
          onClick={() => onSelect(tab.key)}
        >
          <span className="mobile-nav-icon">{tab.icon}</span>
          <span className="mobile-nav-label">{tab.label}</span>
        </button>
      ))}
    </nav>
  );
}
