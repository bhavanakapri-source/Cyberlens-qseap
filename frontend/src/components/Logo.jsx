function Logo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden="true">
      <path d="M16 2.5 4.5 7v8.2c0 7 4.8 12.2 11.5 14.3 6.7-2.1 11.5-7.3 11.5-14.3V7L16 2.5Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <circle cx="16" cy="15" r="5.2" stroke="currentColor" strokeWidth="1.6" />
      <circle cx="16" cy="15" r="1.8" fill="currentColor" />
    </svg>
  );
}
export default Logo;