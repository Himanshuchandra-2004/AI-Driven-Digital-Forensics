/** "Full analysis" backdrop: grid, scanning beam, floating forensic tags. */
const TAGS = ['SYN flood', '192.168.1.14', 'TLS anomaly', 'port 445', 'exfil 2.3 GB', 'score 0.87', 'DNS TXT', 'beacon 60s', 'RF: DDoS', 'IF: anomaly'];

export default function CasesBackdrop() {
  return (
    <div className="analysis-bg" aria-hidden>
      <div className="analysis-scan" />
      {TAGS.map((t, i) => (
        <span key={t} className="analysis-tag"
          style={{ left: `${(i * 13 + 5) % 88}%`, top: `${(i * 23 + 8) % 82}%`, animationDelay: `${i * 0.8}s` }}>{t}</span>
      ))}
    </div>
  );
}
