// One outline icon family: 18px box, 1.5px stroke, round joins.
const PATHS: Record<string, JSX.Element> = {
  overview: (<><path d="M2 4.5c3.5 0 4 4.5 7 4.5M2 13.5c3.5 0 4-4.5 7-4.5" /><path d="M9 9h7" /><rect x="7.5" y="6.5" width="3" height="5" rx="1" /></>),
  traffic: (<><path d="M3 4.5h12M3 9h12M3 13.5h12" /><path d="M1.5 4.5h0M1.5 9h0M1.5 13.5h0" /></>),
  rules: (<><path d="M9 2l6 2.5V9c0 3.5-2.6 6-6 7-3.4-1-6-3.5-6-7V4.5L9 2z" /><path d="M6.5 9h5M6.5 11.5h3" /></>),
  analytics: (<><path d="M3 15V9M7.5 15V4M12 15v-7M16 15v-4" /></>),
  events: (<><path d="M4 3v12M4 5h9l-1.5 2.5L13 10H4" /></>),
  settings: (<><circle cx="9" cy="9" r="2.4" /><path d="M9 1.8v2M9 14.2v2M1.8 9h2M14.2 9h2M3.9 3.9l1.4 1.4M12.7 12.7l1.4 1.4M3.9 14.1l1.4-1.4M12.7 5.3l1.4-1.4" /></>),
  pause: (<><path d="M6.5 4v10M11.5 4v10" /></>),
  play: (<><path d="M6 4l8 5-8 5z" /></>),
  close: (<><path d="M4.5 4.5l9 9M13.5 4.5l-9 9" /></>),
  up: (<><path d="M9 14V4M5 8l4-4 4 4" /></>),
  down: (<><path d="M9 4v10M5 10l4 4 4-4" /></>),
  plus: (<><path d="M9 3.5v11M3.5 9h11" /></>),
  search: (<><circle cx="8" cy="8" r="4.5" /><path d="M11.5 11.5L15 15" /></>),
  arrow: (<><path d="M3.5 9h11M10 4.5L14.5 9 10 13.5" /></>),
  edit: (<><path d="M3 15l1-3.5L12 3.5l2.5 2.5-8 8L3 15z" /></>),
  trash: (<><path d="M3.5 5h11M7 5V3.5h4V5M5 5l.8 9.5h6.4L13 5" /></>),
};

export function Icon({ name, size = 18, title }: { name: keyof typeof PATHS | string; size?: number; title?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 18 18" fill="none" stroke="currentColor" strokeWidth={1.5}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden={title ? undefined : true} role={title ? "img" : undefined}>
      {title && <title>{title}</title>}
      {PATHS[name]}
    </svg>
  );
}

/** PyWall's mark: a postmark ring with the sorted letter at its centre. */
export function Mark({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 28 28" aria-label="PyWall" role="img">
      <circle cx="14" cy="14" r="11" fill="none" stroke="var(--allow)" strokeWidth="2" />
      <circle cx="14" cy="14" r="7" fill="none" stroke="var(--allow)" strokeWidth="1" strokeDasharray="2 2.4" />
      <circle cx="14" cy="14" r="3" fill="var(--allow)" />
    </svg>
  );
}
