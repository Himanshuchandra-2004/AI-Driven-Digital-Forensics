/** Falling digits that match the login mock: cyan / blue / violet columns that fade out behind a bright head. */
import { useEffect, useRef } from 'react';

const DIGITS = '000001111112233445566778899?';
const DARK = ['#12c8ff', '#12c8ff', '#00b4ff', '#2f7bff', '#2f6bff', '#8b5cf6', '#1f4a8f'];
const LIGHT = ['#0077ff', '#0a5fd6', '#6a4bff', '#2f6bff'];

type Col = { x: number; head: number; speed: number; len: number; chars: string[]; color: string; alpha: number };
const rnd = (a: number, b: number) => a + Math.random() * (b - a);
const pick = <T,>(arr: T[]) => arr[Math.floor(Math.random() * arr.length)];

export default function MatrixRain({ size = 16 }: { size?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const c = ref.current!;
    const ctx = c.getContext('2d')!;
    const step = size * 1.38;
    let w = 0, h = 0, raf = 0, frame = 0;
    let cols: Col[] = [];

    const spawn = (x: number, seed: boolean): Col => {
      const len = Math.floor(rnd(12, 42));
      const light = document.documentElement.dataset.theme === 'light';
      return {
        x, len, speed: rnd(0.6, 2.1),
        head: seed ? rnd(-step * 4, h + len * step) : -rnd(0, h * 0.6),
        chars: Array.from({ length: len }, () => pick([...DIGITS])),
        color: pick(light ? LIGHT : DARK),
        alpha: rnd(0.4, 1),
      };
    };
    const resize = () => {
      w = c.width = window.innerWidth;
      h = c.height = window.innerHeight;
      cols = [];
      for (let x = size; x < w; x += size * 1.6) if (Math.random() < 0.78) cols.push(spawn(x, true));
    };
    resize();
    window.addEventListener('resize', resize);

    const draw = () => {
      frame++;
      const light = document.documentElement.dataset.theme === 'light';
      ctx.clearRect(0, 0, w, h);
      ctx.font = `${size}px "JetBrains Mono", "Courier New", monospace`;
      ctx.textAlign = 'center';
      cols.forEach((col, ci) => {
        col.head += col.speed;
        if (frame % 10 === ci % 10) col.chars[Math.floor(Math.random() * col.len)] = pick([...DIGITS]);
        for (let i = 0; i < col.len; i++) {
          const y = col.head - i * step;
          if (y < -step || y > h + step) continue;
          ctx.globalAlpha = col.alpha * Math.pow(1 - i / col.len, 1.5);
          ctx.fillStyle = i === 0 && !light ? '#a8f0ff' : col.color;
          ctx.shadowColor = col.color;
          ctx.shadowBlur = light ? 0 : i < 3 ? 9 : 3;
          ctx.fillText(col.chars[i], col.x, y);
        }
        if (col.head - col.len * step > h) cols[ci] = spawn(col.x, false);
      });
      ctx.globalAlpha = 1;
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener('resize', resize); };
  }, [size]);
  return <canvas ref={ref} className="bg-canvas" />;
}
