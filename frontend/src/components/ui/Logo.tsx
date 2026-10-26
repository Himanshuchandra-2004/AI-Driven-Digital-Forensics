/** Exact logo (cropped from the design mock) with a soft animated glow. */
export default function Logo({ size = 120 }: { size?: number }) {
  return <img src="/logo.png" alt="AI Forensics logo" width={size} height={Math.round(size * 0.877)} className="logo-img" draggable={false} />;
}
