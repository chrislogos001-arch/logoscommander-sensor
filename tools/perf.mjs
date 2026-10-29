// Median time to scan one outbound chunk, measured on this machine.
import { Sensor } from "../sensor/sensor.js";
const size = Number(process.argv[2] || 4096);
const runs = 2000;
const chunk = ("The quick brown fox jumps over the lazy dog. ".repeat(200)).slice(0, size);
const s = new Sensor({ tier: "basic" });
const t = [];
for (let i = 0; i < runs; i++) {
  const t0 = performance.now();
  s.pushOutbound(chunk);
  t.push((performance.now() - t0) * 1000);
}
t.sort((a, b) => a - b);
const q = (p) => t[Math.floor(p * (t.length - 1))].toFixed(1);
console.log(`node ${process.version}, ${size}-char chunks, ${runs} runs: median ${q(0.5)} µs, p99 ${q(0.99)} µs`);
