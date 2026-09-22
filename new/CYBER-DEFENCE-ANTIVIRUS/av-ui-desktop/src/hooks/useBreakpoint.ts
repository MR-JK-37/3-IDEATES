import { useEffect, useState } from 'react';

export type Breakpoint = 'mobile' | 'tablet' | 'desktop';

function detectBreakpoint(width: number): Breakpoint {
  if (width < 640) return 'mobile';
  if (width < 1024) return 'tablet';
  return 'desktop';
}

export function useBreakpoint() {
  const [breakpoint, setBreakpoint] = useState<Breakpoint>(() => detectBreakpoint(window.innerWidth));

  useEffect(() => {
    const updateBreakpoint = () => setBreakpoint(detectBreakpoint(window.innerWidth));
    window.addEventListener('resize', updateBreakpoint);
    return () => window.removeEventListener('resize', updateBreakpoint);
  }, []);

  return breakpoint;
}
