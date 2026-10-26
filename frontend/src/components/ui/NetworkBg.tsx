/** Moving neon-blue network: drifting dots joined by glowing lines. */
import { useEffect, useRef } from 'react';

export default function NetworkBg({ count = 70 }: { count?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current!;
    const ctx = c.getContext('2d')!;
    let w = 0, h = 0, raf = 0;
    let pts: { x: number; y: number; vx: number; vy: number }[] = [];
    const resize = () => {
      w = c.width = window.innerWidth;
      h = c.height = window.innerHeight;
      pts = Array.from({ length: count }, () => ({ x: Math.random() * w, y: Math.random() * h, vx: (Math.random() - 0.5) * 0.6, vy: (Math.random() - 0.5) * 0.6 }));
    };
    resize();
    window.addEventListener('resize', resize);
    const draw = () => {
      const light = document.documentElement.dataset.theme === 'light';
      const rgb = light ? '0,119,255' : '34,211,238';
      ctx.clearRect(0, 0, w, h);
      pts.forEach((p) => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      });
      ctx.shadowBlur = 0;
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const d = Math.hypot(pts[i].x - pts[j].x, pts[i].y - pts[j].y);
          if (d < 170) {
            ctx.strokeStyle = `rgba(${rgb},${(1 - d / 170) * (light ? 0.3 : 0.32)})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y); ctx.stroke();
          }
        }
      }
      ctx.fillStyle = `rgb(${rgb})`;
      ctx.shadowColor = `rgb(${rgb})`;
      ctx.shadowBlur = light ? 0 : 7;
      pts.forEach((p) => { ctx.beginPath(); ctx.arc(p.x, p.y, 2, 0, Math.PI * 2); ctx.fill(); });
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
  }, [count]);
  return <canvas ref={ref} className="bg-canvas" />;
}
