import type { CSSProperties, ReactNode } from 'react';

type CardProps = {
  children: ReactNode;
  variant?: 'default' | 'glass' | 'solid';
  glow?: boolean;
  glowColor?: string;
  interactive?: boolean;
  className?: string;
};

export function Card({
  children,
  variant = 'glass',
  glow = false,
  glowColor,
  interactive = false,
  className = '',
}: CardProps) {
  const classes = [
    'cs-card',
    variant === 'glass' ? 'cs-card-glass' : '',
    variant === 'solid' ? 'cs-card-solid' : '',
    interactive ? 'cs-card-interactive' : '',
    glow ? 'cs-card-glow' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  const style = glow && glowColor ? ({ ['--card-glow' as string]: glowColor } as CSSProperties) : undefined;

  return (
    <div className={classes} style={style}>
      {children}
    </div>
  );
}
